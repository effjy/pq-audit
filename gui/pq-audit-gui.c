/* pq-audit-gui — a small GTK3 front-end for the pq-audit CLI.
 *
 * Design: the GUI never links the pq-audit core. It shells out to the
 * binary via `/bin/sh -c <pipeline>` and streams stdout+stderr into a
 * console view. Privileged operations (reading root-only logs) are wrapped in
 * a single `pkexec sh -c ...` so the user is prompted for a password once,
 * not once per log line.
 *
 *   cc $(pkg-config --cflags gtk+-3.0) pq-audit-gui.c \
 *      $(pkg-config --libs gtk+-3.0) -o pq-audit-gui
 */
#include <gtk/gtk.h>
#include <string.h>
#include <sys/wait.h>

/* signature algorithms (whatever the liboqs build enables) */
static const char *SIG_ALGS[] = {
    "ml-dsa-44", "ml-dsa-65", "ml-dsa-87",
    "slh-dsa-128f", "slh-dsa-192f", "slh-dsa-256f", NULL
};
/* hash-based anchors used for the forward-secure manifest */
static const char *ANCHOR_ALGS[] = {
    "slh-dsa-128f", "slh-dsa-192f", "slh-dsa-256f", NULL
};

typedef struct {
    GtkWidget *win;
    GtkWidget *bin_entry;     /* path to pq-audit binary            */
    GtkWidget *dir_entry;     /* audit directory (--dir)            */
    GtkWidget *key_entry;     /* secret key (--key)                 */
    GtkWidget *pub_entry;     /* public key (--pub)                 */
    GtkWidget *alg_combo;     /* keygen / fs-init epoch algorithm   */
    GtkWidget *log_entry;     /* log file to feed                   */
    GtkWidget *src_spin;      /* --src                              */
    GtkWidget *level_spin;    /* --level                            */
    GtkWidget *root_check;    /* run privileged via pkexec          */
    GtkWidget *sink_entry;    /* off-box seal mirror (--sink)       */
    GtkWidget *sealfile_entry;/* trusted seal copy (verify --seal-file) */
    /* forward security */
    GtkWidget *ring_entry;    /* secret keyring (--ring, *.fsring)  */
    GtkWidget *fspub_entry;   /* epoch public bundle (--fspub)      */
    GtkWidget *anchorpub_entry;/* anchor public (--anchor)          */
    GtkWidget *anchor_combo;  /* fs-init anchor algorithm           */
    GtkWidget *epochs_spin;   /* fs-init --epochs                   */
    /* runtime */
    GtkWidget *console;
    GtkWidget *status;
    GtkWidget *run_buttons;   /* every action button, disabled while busy */
    gboolean   busy;
} App;

/* ---- console helpers ---------------------------------------------------- */

static void console_append(App *a, const char *s)
{
    GtkTextBuffer *b = gtk_text_view_get_buffer(GTK_TEXT_VIEW(a->console));
    GtkTextIter end;
    gtk_text_buffer_get_end_iter(b, &end);
    gtk_text_buffer_insert(b, &end, s, -1);
    gtk_text_buffer_get_end_iter(b, &end);
    GtkTextMark *m = gtk_text_buffer_create_mark(b, NULL, &end, FALSE);
    gtk_text_view_scroll_mark_onscreen(GTK_TEXT_VIEW(a->console), m);
    gtk_text_buffer_delete_mark(b, m);
}

static void set_status(App *a, const char *s)
{
    guint id = gtk_statusbar_get_context_id(GTK_STATUSBAR(a->status), "main");
    gtk_statusbar_pop(GTK_STATUSBAR(a->status), id);
    gtk_statusbar_push(GTK_STATUSBAR(a->status), id, s);
}

static const char *entry_text(GtkWidget *e)
{
    return gtk_entry_get_text(GTK_ENTRY(e));
}

static gchar *combo_text(GtkWidget *c)
{
    return gtk_combo_box_text_get_active_text(GTK_COMBO_BOX_TEXT(c));
}

/* ---- async command runner ---------------------------------------------- */

typedef struct {
    App        *app;
    GIOChannel *out, *err;
    GPid        pid;
    char        what[64];
} Job;

static gboolean drain(GIOChannel *src, GIOCondition cond, gpointer data)
{
    Job *j = data;
    if (cond & (G_IO_IN | G_IO_HUP)) {
        gchar *line = NULL; gsize len = 0;
        GIOStatus st;
        while ((st = g_io_channel_read_line(src, &line, &len, NULL, NULL))
               == G_IO_STATUS_NORMAL) {
            console_append(j->app, line);
            g_free(line); line = NULL;
        }
        if (st == G_IO_STATUS_EOF) {
            g_io_channel_shutdown(src, FALSE, NULL);
            return G_SOURCE_REMOVE;
        }
    }
    if (cond & G_IO_HUP) {
        g_io_channel_shutdown(src, FALSE, NULL);
        return G_SOURCE_REMOVE;
    }
    return G_SOURCE_CONTINUE;
}

static void on_child_exit(GPid pid, gint status, gpointer data)
{
    Job *j = data;
    App *a = j->app;
    char buf[128];
    int code = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
    /* pq-audit exit codes: 0 ok, 2 tamper/invalid, 1 usage/IO */
    const char *verdict = code == 0 ? "OK" :
                          code == 2 ? "TAMPER/INVALID (exit 2)" :
                                      "ERROR";
    g_snprintf(buf, sizeof buf, "\n--- %s finished: %s ---\n\n", j->what, verdict);
    console_append(a, buf);
    g_snprintf(buf, sizeof buf, "%s: %s", j->what, verdict);
    set_status(a, buf);

    g_spawn_close_pid(pid);
    a->busy = FALSE;
    gtk_widget_set_sensitive(a->run_buttons, TRUE);
    g_free(j);
}

static void run_argv(App *a, char **argv, const char *what)
{
    if (a->busy) {
        console_append(a, "[busy — wait for the current command]\n");
        return;
    }
    GError *e = NULL;
    gint out_fd, err_fd;
    GPid pid;
    {
        gchar *joined = g_strjoinv(" ", argv);
        char *msg = g_strdup_printf("$ %s\n", joined);
        console_append(a, msg);
        g_free(msg); g_free(joined);
    }
    if (!g_spawn_async_with_pipes(NULL, argv, NULL,
            G_SPAWN_DO_NOT_REAP_CHILD | G_SPAWN_SEARCH_PATH,
            NULL, NULL, &pid, NULL, &out_fd, &err_fd, &e)) {
        char *msg = g_strdup_printf("spawn failed: %s\n", e->message);
        console_append(a, msg); g_free(msg); g_error_free(e);
        return;
    }
    a->busy = TRUE;
    gtk_widget_set_sensitive(a->run_buttons, FALSE);

    Job *j = g_new0(Job, 1);
    j->app = a; j->pid = pid;
    g_strlcpy(j->what, what, sizeof j->what);

    j->out = g_io_channel_unix_new(out_fd);
    j->err = g_io_channel_unix_new(err_fd);
    g_io_channel_set_close_on_unref(j->out, TRUE);
    g_io_channel_set_close_on_unref(j->err, TRUE);
    g_io_add_watch(j->out, G_IO_IN | G_IO_HUP, drain, j);
    g_io_add_watch(j->err, G_IO_IN | G_IO_HUP, drain, j);
    g_child_watch_add(pid, on_child_exit, j);
}

/* Run a shell pipeline; if `privileged`, wrap in pkexec so one prompt
 * covers the whole pipeline. */
static void run_shell(App *a, const char *pipeline, const char *what,
                      gboolean privileged)
{
    char *argv[5];
    int n = 0;
    if (privileged) { argv[n++] = "pkexec"; argv[n++] = "/bin/sh"; }
    else            { argv[n++] = "/bin/sh"; }
    argv[n++] = "-c";
    argv[n++] = (char *)pipeline;
    argv[n]   = NULL;
    run_argv(a, argv, what);
}

/* ---- field helpers ------------------------------------------------------ */

static gboolean require(App *a, GtkWidget *e, const char *label)
{
    if (entry_text(e)[0] == '\0') {
        char *m = g_strdup_printf("[set %s first]\n", label);
        console_append(a, m); g_free(m);
        set_status(a, "missing field");
        return FALSE;
    }
    return TRUE;
}

static gboolean has(GtkWidget *e) { return entry_text(e)[0] != '\0'; }

/* strip a trailing suffix (e.g. ".key", ".fsring") to recover an --out base */
static char *base_of(const char *s, const char *suffix, const char *fallback)
{
    char *out = s[0] ? g_strdup(s) : g_strdup(fallback);
    char *p = g_strrstr(out, suffix);
    if (p && p[strlen(suffix)] == '\0') *p = '\0';
    return out;
}

/* ---- button handlers ---------------------------------------------------- */

static void on_init(GtkButton *b, gpointer d)
{
    (void)b; App *a = d;
    if (!require(a, a->bin_entry, "binary") || !require(a, a->dir_entry, "directory"))
        return;
    char *cmd = g_strdup_printf("%s init --dir %s",
        entry_text(a->bin_entry), entry_text(a->dir_entry));
    run_shell(a, cmd, "init", FALSE);
    g_free(cmd);
}

static void on_keygen(GtkButton *b, gpointer d)
{
    (void)b; App *a = d;
    if (!require(a, a->bin_entry, "binary")) return;
    char *base = base_of(entry_text(a->key_entry), ".key", "anchor");
    char *alg  = combo_text(a->alg_combo);
    char *cmd  = g_strdup_printf("%s keygen --out %s --alg %s",
        entry_text(a->bin_entry), base, alg);
    run_shell(a, cmd, "keygen", FALSE);
    char *k = g_strdup_printf("%s.key", base);
    char *p = g_strdup_printf("%s.pub", base);
    gtk_entry_set_text(GTK_ENTRY(a->key_entry), k);
    gtk_entry_set_text(GTK_ENTRY(a->pub_entry), p);
    g_free(k); g_free(p); g_free(base); g_free(alg); g_free(cmd);
}

static void on_fsinit(GtkButton *b, gpointer d)
{
    (void)b; App *a = d;
    if (!require(a, a->bin_entry, "binary")) return;
    char *base   = base_of(entry_text(a->ring_entry), ".fsring", "fs");
    char *alg    = combo_text(a->alg_combo);
    char *anchor = combo_text(a->anchor_combo);
    int   epochs = gtk_spin_button_get_value_as_int(GTK_SPIN_BUTTON(a->epochs_spin));
    char *cmd = g_strdup_printf("%s fs-init --out %s --alg %s --anchor %s --epochs %d",
        entry_text(a->bin_entry), base, alg, anchor, epochs);
    run_shell(a, cmd, "fs-init", FALSE);
    /* prefill the ring + verifier bundle fields */
    char *r = g_strdup_printf("%s.fsring", base);
    char *fp = g_strdup_printf("%s.fspub", base);
    char *ap = g_strdup_printf("%s.anchor.pub", base);
    gtk_entry_set_text(GTK_ENTRY(a->ring_entry), r);
    gtk_entry_set_text(GTK_ENTRY(a->fspub_entry), fp);
    gtk_entry_set_text(GTK_ENTRY(a->anchorpub_entry), ap);
    g_free(r); g_free(fp); g_free(ap);
    g_free(base); g_free(alg); g_free(anchor); g_free(cmd);
}

static void on_fsadvance(GtkButton *b, gpointer d)
{
    (void)b; App *a = d;
    if (!require(a, a->bin_entry, "binary") || !require(a, a->ring_entry, "keyring"))
        return;
    char *cmd = g_strdup_printf("%s fs-advance --ring %s",
        entry_text(a->bin_entry), entry_text(a->ring_entry));
    run_shell(a, cmd, "fs-advance", FALSE);
    g_free(cmd);
}

static void on_feed(GtkButton *b, gpointer d)
{
    (void)b; App *a = d;
    if (!require(a, a->bin_entry, "binary") ||
        !require(a, a->dir_entry, "directory") ||
        !require(a, a->log_entry, "log file")) return;

    int src   = gtk_spin_button_get_value_as_int(GTK_SPIN_BUTTON(a->src_spin));
    int level = gtk_spin_button_get_value_as_int(GTK_SPIN_BUTTON(a->level_spin));
    gboolean priv = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(a->root_check));

    /* whole ingest loop in one shell child → one pkexec prompt. */
    char *qbin = g_shell_quote(entry_text(a->bin_entry));
    char *qdir = g_shell_quote(entry_text(a->dir_entry));
    char *qlog = g_shell_quote(entry_text(a->log_entry));
    char *cmd = g_strdup_printf(
        "n=0; while IFS= read -r line; do "
        "printf '%%s' \"$line\" | %s log --dir %s --src %d --level %d >/dev/null || exit 1; "
        "n=$((n+1)); done < %s; echo \"fed $n line(s) from %s\"",
        qbin, qdir, src, level, qlog, entry_text(a->log_entry));
    run_shell(a, cmd, "feed", priv);
    g_free(qbin); g_free(qdir); g_free(qlog); g_free(cmd);
}

static void on_seal(GtkButton *b, gpointer d)
{
    (void)b; App *a = d;
    if (!require(a, a->bin_entry, "binary") || !require(a, a->dir_entry, "directory"))
        return;
    /* prefer the forward-secure ring if set; else the single key */
    GString *cmd = g_string_new(NULL);
    g_string_append_printf(cmd, "%s seal --dir %s",
        entry_text(a->bin_entry), entry_text(a->dir_entry));
    if (has(a->ring_entry)) {
        g_string_append_printf(cmd, " --ring %s", entry_text(a->ring_entry));
    } else {
        if (!require(a, a->key_entry, "secret key or keyring")) {
            g_string_free(cmd, TRUE); return;
        }
        g_string_append_printf(cmd, " --key %s", entry_text(a->key_entry));
    }
    if (has(a->sink_entry))
        g_string_append_printf(cmd, " --sink %s", entry_text(a->sink_entry));
    run_shell(a, cmd->str, "seal", FALSE);
    g_string_free(cmd, TRUE);
}

static void on_verify(GtkButton *b, gpointer d)
{
    (void)b; App *a = d;
    if (!require(a, a->bin_entry, "binary") || !require(a, a->dir_entry, "directory"))
        return;
    GString *cmd = g_string_new(NULL);
    g_string_append_printf(cmd, "%s verify --dir %s",
        entry_text(a->bin_entry), entry_text(a->dir_entry));
    if (has(a->fspub_entry) && has(a->anchorpub_entry))
        g_string_append_printf(cmd, " --fspub %s --anchor %s",
            entry_text(a->fspub_entry), entry_text(a->anchorpub_entry));
    else if (has(a->pub_entry))
        g_string_append_printf(cmd, " --pub %s", entry_text(a->pub_entry));
    if (has(a->sealfile_entry))
        g_string_append_printf(cmd, " --seal-file %s", entry_text(a->sealfile_entry));
    run_shell(a, cmd->str, "verify", FALSE);
    g_string_free(cmd, TRUE);
}

/* ---- file/dir pickers --------------------------------------------------- */

static void pick(App *a, GtkWidget *target, GtkFileChooserAction action,
                 const char *title)
{
    GtkWidget *dlg = gtk_file_chooser_dialog_new(title, GTK_WINDOW(a->win),
        action, "_Cancel", GTK_RESPONSE_CANCEL, "_Select", GTK_RESPONSE_ACCEPT,
        NULL);
    if (gtk_dialog_run(GTK_DIALOG(dlg)) == GTK_RESPONSE_ACCEPT) {
        char *f = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(dlg));
        if (f) { gtk_entry_set_text(GTK_ENTRY(target), f); g_free(f); }
    }
    gtk_widget_destroy(dlg);
}

/* generic picker that reads which entry to fill from the button's data */
static void browse_open(GtkButton *b, gpointer d)
{
    App *a = d;
    GtkWidget *target = g_object_get_data(G_OBJECT(b), "target");
    pick(a, target, GTK_FILE_CHOOSER_ACTION_OPEN, "Choose file");
}
static void browse_save(GtkButton *b, gpointer d)
{
    App *a = d;
    GtkWidget *target = g_object_get_data(G_OBJECT(b), "target");
    pick(a, target, GTK_FILE_CHOOSER_ACTION_SAVE, "Choose file");
}
static void browse_folder(GtkButton *b, gpointer d)
{
    App *a = d;
    GtkWidget *target = g_object_get_data(G_OBJECT(b), "target");
    pick(a, target, GTK_FILE_CHOOSER_ACTION_SELECT_FOLDER, "Choose folder");
}

/* ---- UI construction ---------------------------------------------------- */

/* one labeled row in a grid: label | entry | optional Browse button */
static void grid_row(GtkGrid *g, int row, const char *label, GtkWidget *entry,
                     App *a, GCallback browse_cb)
{
    GtkWidget *l = gtk_label_new(label);
    gtk_label_set_xalign(GTK_LABEL(l), 0.0);
    gtk_grid_attach(g, l, 0, row, 1, 1);
    gtk_widget_set_hexpand(entry, TRUE);
    gtk_grid_attach(g, entry, 1, row, 1, 1);
    if (browse_cb) {
        GtkWidget *btn = gtk_button_new_with_label("Browse…");
        g_object_set_data(G_OBJECT(btn), "target", entry);
        g_signal_connect(btn, "clicked", browse_cb, a);
        gtk_grid_attach(g, btn, 2, row, 1, 1);
    }
}

static GtkWidget *frame(const char *title, GtkWidget *child)
{
    GtkWidget *f = gtk_frame_new(title);
    gtk_container_set_border_width(GTK_CONTAINER(child), 8);
    gtk_container_add(GTK_CONTAINER(f), child);
    return f;
}

static GtkWidget *new_grid(void)
{
    GtkWidget *g = gtk_grid_new();
    gtk_grid_set_row_spacing(GTK_GRID(g), 4);
    gtk_grid_set_column_spacing(GTK_GRID(g), 6);
    return g;
}

static GtkWidget *combo(const char **items, const char *active)
{
    GtkWidget *c = gtk_combo_box_text_new();
    int sel = 0;
    for (int i = 0; items[i]; i++) {
        gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(c), items[i]);
        if (active && g_strcmp0(items[i], active) == 0) sel = i;
    }
    gtk_combo_box_set_active(GTK_COMBO_BOX(c), sel);
    return c;
}

static void add_action(App *a, GtkBox *box, const char *label, GCallback cb)
{
    GtkWidget *btn = gtk_button_new_with_label(label);
    g_signal_connect(btn, "clicked", cb, a);
    gtk_box_pack_start(box, btn, TRUE, TRUE, 0);
}

static void activate(GtkApplication *app, gpointer data)
{
    App *a = data;
    a->win = gtk_application_window_new(app);
    gtk_window_set_title(GTK_WINDOW(a->win), "pq-audit");

    /* Window/taskbar icon. When installed, the themed icon "dev.pqaudit.gui"
     * (matching the app-id and the .desktop StartupWMClass) is found by name.
     * When running from the build dir, fall back to the SVG on disk. */
    gtk_window_set_default_icon_name("dev.pqaudit.gui");
    gtk_window_set_icon_name(GTK_WINDOW(a->win), "dev.pqaudit.gui");
    if (!gtk_icon_theme_has_icon(gtk_icon_theme_get_default(), "dev.pqaudit.gui")) {
        const char *paths[] = {
            "dev.pqaudit.gui.svg", "gui/dev.pqaudit.gui.svg", NULL
        };
        for (int i = 0; paths[i]; i++) {
            GdkPixbuf *pb = gdk_pixbuf_new_from_file(paths[i], NULL);
            if (pb) {
                gtk_window_set_icon(GTK_WINDOW(a->win), pb);
                gtk_window_set_default_icon(pb);
                g_object_unref(pb);
                break;
            }
        }
    }
    gtk_window_set_default_size(GTK_WINDOW(a->win), 720, 540);
    gtk_container_set_border_width(GTK_CONTAINER(a->win), 10);

    GtkWidget *root = gtk_box_new(GTK_ORIENTATION_VERTICAL, 8);
    gtk_container_add(GTK_CONTAINER(a->win), root);

    /* ---- Audit log & keys ---- */
    GtkWidget *g1 = new_grid();
    a->bin_entry = gtk_entry_new();
    gtk_entry_set_text(GTK_ENTRY(a->bin_entry), "pq-audit");
    a->dir_entry = gtk_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(a->dir_entry), "audit directory, e.g. ./klog");
    a->key_entry = gtk_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(a->key_entry), "anchor.key (single-key seal)");
    a->pub_entry = gtk_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(a->pub_entry), "anchor.pub (verify, optional)");
    a->alg_combo = combo(SIG_ALGS, "ml-dsa-65");
    grid_row(GTK_GRID(g1), 0, "pq-audit binary", a->bin_entry, a, G_CALLBACK(browse_open));
    grid_row(GTK_GRID(g1), 1, "Audit dir", a->dir_entry, a, G_CALLBACK(browse_folder));
    grid_row(GTK_GRID(g1), 2, "Secret key", a->key_entry, a, G_CALLBACK(browse_open));
    grid_row(GTK_GRID(g1), 3, "Public key", a->pub_entry, a, G_CALLBACK(browse_open));
    grid_row(GTK_GRID(g1), 4, "Algorithm", a->alg_combo, a, NULL);
    gtk_box_pack_start(GTK_BOX(root), frame("Audit log & keys", g1), FALSE, FALSE, 0);

    /* ---- Feed ---- */
    GtkWidget *g2 = new_grid();
    a->log_entry = gtk_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(a->log_entry), "/var/log/kern.log");
    grid_row(GTK_GRID(g2), 0, "Log file", a->log_entry, a, G_CALLBACK(browse_open));
    GtkWidget *opts = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
    gtk_box_pack_start(GTK_BOX(opts), gtk_label_new("src"), FALSE, FALSE, 0);
    a->src_spin = gtk_spin_button_new_with_range(0, 255, 1);
    gtk_spin_button_set_value(GTK_SPIN_BUTTON(a->src_spin), 2);
    gtk_box_pack_start(GTK_BOX(opts), a->src_spin, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(opts), gtk_label_new("level"), FALSE, FALSE, 0);
    a->level_spin = gtk_spin_button_new_with_range(0, 7, 1);
    gtk_spin_button_set_value(GTK_SPIN_BUTTON(a->level_spin), 3);
    gtk_box_pack_start(GTK_BOX(opts), a->level_spin, FALSE, FALSE, 0);
    a->root_check = gtk_check_button_new_with_label("Read as root (pkexec)");
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(a->root_check), TRUE);
    gtk_box_pack_start(GTK_BOX(opts), a->root_check, FALSE, FALSE, 12);
    gtk_grid_attach(GTK_GRID(g2), opts, 1, 1, 2, 1);
    gtk_box_pack_start(GTK_BOX(root), frame("Feed a log file", g2), FALSE, FALSE, 0);

    /* ---- Forward security & off-box sinks ---- */
    GtkWidget *g3 = new_grid();
    a->ring_entry = gtk_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(a->ring_entry), "fs.fsring (secret keyring — seal --ring)");
    a->fspub_entry = gtk_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(a->fspub_entry), "fs.fspub (verify --fspub)");
    a->anchorpub_entry = gtk_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(a->anchorpub_entry), "fs.anchor.pub (verify --anchor)");
    a->anchor_combo = combo(ANCHOR_ALGS, "slh-dsa-128f");
    a->epochs_spin = gtk_spin_button_new_with_range(1, 100000, 1);
    gtk_spin_button_set_value(GTK_SPIN_BUTTON(a->epochs_spin), 30);
    a->sink_entry = gtk_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(a->sink_entry), "/mnt/worm/audit.seal (seal --sink, optional)");
    a->sealfile_entry = gtk_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(a->sealfile_entry), "trusted seal copy (verify --seal-file, optional)");
    grid_row(GTK_GRID(g3), 0, "Keyring", a->ring_entry, a, G_CALLBACK(browse_save));
    grid_row(GTK_GRID(g3), 1, "Epoch pub", a->fspub_entry, a, G_CALLBACK(browse_open));
    grid_row(GTK_GRID(g3), 2, "Anchor pub", a->anchorpub_entry, a, G_CALLBACK(browse_open));
    grid_row(GTK_GRID(g3), 3, "Anchor alg", a->anchor_combo, a, NULL);
    grid_row(GTK_GRID(g3), 4, "Epochs", a->epochs_spin, a, NULL);
    grid_row(GTK_GRID(g3), 5, "Sink (off-box)", a->sink_entry, a, G_CALLBACK(browse_save));
    grid_row(GTK_GRID(g3), 6, "Seal file (verify)", a->sealfile_entry, a, G_CALLBACK(browse_open));
    GtkWidget *fsbtns = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
    add_action(a, GTK_BOX(fsbtns), "FS-Init", G_CALLBACK(on_fsinit));
    add_action(a, GTK_BOX(fsbtns), "FS-Advance", G_CALLBACK(on_fsadvance));
    gtk_grid_attach(GTK_GRID(g3), fsbtns, 1, 7, 2, 1);
    /* tallest section — collapsed by default so the window fits small screens */
    GtkWidget *fsexp = gtk_expander_new("Forward security & off-box sinks  (advanced)");
    gtk_container_set_border_width(GTK_CONTAINER(g3), 8);
    gtk_container_add(GTK_CONTAINER(fsexp), g3);
    gtk_expander_set_expanded(GTK_EXPANDER(fsexp), FALSE);
    gtk_box_pack_start(GTK_BOX(root), fsexp, FALSE, FALSE, 0);

    /* ---- main actions ---- */
    a->run_buttons = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
    add_action(a, GTK_BOX(a->run_buttons), "Init",   G_CALLBACK(on_init));
    add_action(a, GTK_BOX(a->run_buttons), "Keygen", G_CALLBACK(on_keygen));
    add_action(a, GTK_BOX(a->run_buttons), "Feed →", G_CALLBACK(on_feed));
    add_action(a, GTK_BOX(a->run_buttons), "Seal",   G_CALLBACK(on_seal));
    add_action(a, GTK_BOX(a->run_buttons), "Verify", G_CALLBACK(on_verify));
    /* the FS buttons share the busy lock too */
    gtk_widget_set_sensitive(a->run_buttons, TRUE);
    gtk_box_pack_start(GTK_BOX(root), a->run_buttons, FALSE, FALSE, 0);

    /* ---- console ---- */
    a->console = gtk_text_view_new();
    gtk_text_view_set_editable(GTK_TEXT_VIEW(a->console), FALSE);
    gtk_text_view_set_monospace(GTK_TEXT_VIEW(a->console), TRUE);
    gtk_text_view_set_wrap_mode(GTK_TEXT_VIEW(a->console), GTK_WRAP_WORD_CHAR);
    GtkWidget *scroll = gtk_scrolled_window_new(NULL, NULL);
    gtk_container_add(GTK_CONTAINER(scroll), a->console);
    /* small minimum so the window can shrink; it still expands to fill */
    gtk_widget_set_size_request(scroll, -1, 100);
    gtk_box_pack_start(GTK_BOX(root), scroll, TRUE, TRUE, 0);

    a->status = gtk_statusbar_new();
    gtk_box_pack_start(GTK_BOX(root), a->status, FALSE, FALSE, 0);
    set_status(a, "ready");

    gtk_widget_show_all(a->win);
}

int main(int argc, char **argv)
{
    App a = {0};
    GtkApplication *app = gtk_application_new("dev.pqaudit.gui",
                                              G_APPLICATION_DEFAULT_FLAGS);
    g_signal_connect(app, "activate", G_CALLBACK(activate), &a);
    int rc = g_application_run(G_APPLICATION(app), argc, argv);
    g_object_unref(app);
    return rc;
}
