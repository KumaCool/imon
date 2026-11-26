//go:build linux && cgo && desktop

#include "gtk_linux.h"
#include "vendor/webview.h"
#include <cstring>

extern "C" void desktopGTKCancel(uintptr_t handle);
extern "C" void desktopGTKMessage(uintptr_t handle, uintptr_t reply, char *operation, char *payload);

namespace {
constexpr char scheme[] = "imon";
constexpr char app_url[] = "imon://panel/";
constexpr char bridge[] = "imonNative";

struct Session {
  uintptr_t handle;
  const char *proof;
  GBytes *assets[3];
  WebKitWebView *view;
  GtkWindow *window;
  GList *choosers;
  unsigned pending;
  int failure;
  bool closed;
};
Session *current;

struct Reply {
  Session *session;
  WebKitScriptMessageReply *message;
  JSCContext *context;
  gchar *json;
  gchar *error;
  GBytes *script;
  GtkFileChooserNative *chooser;
};

int asset_index(const char *uri, bool fragment) {
  if (!uri) return -1;
  GUri *parts = g_uri_parse(uri, G_URI_FLAGS_ENCODED, nullptr);
  if (!parts) return -1;
  const char *anchor = g_uri_get_fragment(parts);
  int index = -1;
  if (g_strcmp0(g_uri_get_scheme(parts), scheme) == 0 &&
      g_strcmp0(g_uri_get_host(parts), "panel") == 0 && !g_uri_get_userinfo(parts) &&
      g_uri_get_port(parts) == -1 && !g_uri_get_query(parts) && (!anchor || fragment)) {
    const char *path = g_uri_get_path(parts);
    if (g_strcmp0(path, "/") == 0 && (!anchor || !*anchor || *anchor == '?')) index = 0;
    else if (!anchor && g_strcmp0(path, "/app.css") == 0) index = 1;
    else if (!anchor && g_strcmp0(path, "/app.js") == 0) index = 2;
  }
  g_uri_unref(parts);
  return index;
}

void scheme_request(WebKitURISchemeRequest *request, gpointer) {
  const int index = asset_index(webkit_uri_scheme_request_get_uri(request), false);
  if (!current || current->closed || index < 0 ||
      webkit_uri_scheme_request_get_web_view(request) != current->view ||
      g_strcmp0(webkit_uri_scheme_request_get_http_method(request), "GET") != 0) {
    GError *error = g_error_new_literal(G_IO_ERROR, G_IO_ERROR_NOT_FOUND, "Local asset unavailable");
    webkit_uri_scheme_request_finish_error(request, error);
    g_error_free(error);
    return;
  }
  static const char *mime[] = {"text/html; charset=utf-8", "text/css; charset=utf-8", "text/javascript; charset=utf-8"};
  GBytes *bytes = current->assets[index];
  GInputStream *stream = g_memory_input_stream_new_from_bytes(bytes);
  WebKitURISchemeResponse *response = webkit_uri_scheme_response_new(stream, static_cast<gint64>(g_bytes_get_size(bytes)));
  webkit_uri_scheme_response_set_content_type(response, mime[index]);
  SoupMessageHeaders *headers = soup_message_headers_new(SOUP_MESSAGE_HEADERS_RESPONSE);
  soup_message_headers_append(headers, "Content-Type", mime[index]);
  soup_message_headers_append(headers, "Content-Security-Policy",
    "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; "
    "frame-src 'none'; frame-ancestors 'none'; form-action 'none'; base-uri 'none'");
  soup_message_headers_append(headers, "X-Content-Type-Options", "nosniff");
  webkit_uri_scheme_response_set_http_headers(response, headers);
  webkit_uri_scheme_request_finish_with_response(request, response);
  g_object_unref(response);
  g_object_unref(stream);
}

gboolean decide_policy(WebKitWebView *, WebKitPolicyDecision *decision, WebKitPolicyDecisionType type, gpointer data) {
  if (type == WEBKIT_POLICY_DECISION_TYPE_RESPONSE) return FALSE;
  auto *session = static_cast<Session *>(data);
  auto *navigation = WEBKIT_NAVIGATION_POLICY_DECISION(decision);
  WebKitNavigationAction *action = webkit_navigation_policy_decision_get_navigation_action(navigation);
  const char *uri = webkit_uri_request_get_uri(webkit_navigation_action_get_request(action));
  if (type == WEBKIT_POLICY_DECISION_TYPE_NAVIGATION_ACTION && asset_index(uri, true) == 0) return FALSE;
  if (!session->closed && uri && g_str_has_prefix(uri, "https://") &&
      webkit_navigation_action_get_navigation_type(action) == WEBKIT_NAVIGATION_TYPE_LINK_CLICKED &&
      webkit_navigation_action_is_user_gesture(action)) {
    GUri *external = g_uri_parse(uri, G_URI_FLAGS_NONE, nullptr);
    if (external && g_uri_get_host(external) && !g_uri_get_userinfo(external))
      gtk_show_uri_on_window(session->window, uri, GDK_CURRENT_TIME, nullptr);
    if (external) g_uri_unref(external);
  }
  webkit_policy_decision_ignore(decision);
  return TRUE;
}

void finish(Reply *reply, JSCValue *value, const char *problem) {
  if (!reply->session->closed) {
    if (problem) webkit_script_message_reply_return_error_message(reply->message, problem);
    else webkit_script_message_reply_return_value(reply->message, value);
  }
  if (value) g_object_unref(value);
  webkit_script_message_reply_unref(reply->message);
  g_object_unref(reply->context);
  g_free(reply->json);
  g_free(reply->error);
  if (reply->script) g_bytes_unref(reply->script);
  --reply->session->pending;
  delete reply;
}

void choose_response(GtkNativeDialog *dialog, gint response, gpointer data) {
  auto *reply = static_cast<Reply *>(data);
  auto *session = reply->session;
  char *path = response == GTK_RESPONSE_ACCEPT && !session->closed
    ? gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(dialog)) : nullptr;
  session->choosers = g_list_remove(session->choosers, reply);
  gtk_native_dialog_destroy(dialog);
  g_object_unref(dialog);
  JSCValue *out = jsc_value_new_object(reply->context, nullptr, nullptr);
  const char *problem = nullptr;
  if (reply->script) {
    bool saved = false;
    if (path) {
      gsize size = 0;
      const auto *bytes = static_cast<const char *>(g_bytes_get_data(reply->script, &size));
      saved = g_file_set_contents_full(path, bytes, static_cast<gssize>(size), G_FILE_SET_CONTENTS_CONSISTENT, 0600, nullptr);
      if (!saved) problem = "Could not save the maintenance script";
    }
    JSCValue *flag = jsc_value_new_boolean(reply->context, saved);
    jsc_value_object_set_property(out, "saved", flag);
    g_object_unref(flag);
  } else {
    if (path && !g_utf8_validate(path, -1, nullptr)) problem = "The selected path must be UTF-8";
    JSCValue *selection = jsc_value_new_string(reply->context, path && !problem ? path : "");
    jsc_value_object_set_property(out, "path", selection);
    g_object_unref(selection);
  }
  JSCValue *canceled = jsc_value_new_boolean(reply->context, !path);
  jsc_value_object_set_property(out, "canceled", canceled);
  g_object_unref(canceled);
  g_free(path);
  finish(reply, out, problem);
}

void chooser(Reply *reply) {
  if (reply->session->closed) {
    finish(reply, nullptr, "Desktop window closed");
    return;
  }
  const bool save = reply->script != nullptr;
  reply->chooser = gtk_file_chooser_native_new(save ? "Save maintenance script" : "Choose SSH private key",
    reply->session->window, save ? GTK_FILE_CHOOSER_ACTION_SAVE : GTK_FILE_CHOOSER_ACTION_OPEN,
    save ? "_Save" : "_Open", "_Cancel");
  auto *picker = GTK_FILE_CHOOSER(reply->chooser);
  gtk_file_chooser_set_local_only(picker, TRUE);
  if (save) {
    gtk_file_chooser_set_current_name(picker, "firewall-maintain.sh");
    gtk_file_chooser_set_do_overwrite_confirmation(picker, TRUE);
  } else {
    gtk_file_chooser_set_show_hidden(picker, TRUE);
  }
  reply->session->choosers = g_list_prepend(reply->session->choosers, reply);
  g_signal_connect(reply->chooser, "response", G_CALLBACK(choose_response), reply);
  gtk_native_dialog_show(GTK_NATIVE_DIALOG(reply->chooser));
}

gboolean bridge_message(WebKitUserContentManager *, JSCValue *value, WebKitScriptMessageReply *message, gpointer data) {
  auto *session = static_cast<Session *>(data);
  if (session->closed || asset_index(webkit_web_view_get_uri(session->view), true) != 0 || !jsc_value_is_string(value)) {
    webkit_script_message_reply_return_error_message(message, "Invalid desktop message");
    return TRUE;
  }
  char *body = jsc_value_to_string(value);
  gchar **fields = g_strsplit(body, "\n", 3);
  if (g_strv_length(fields) != 3 || strlen(body) > 1024 * 1024 ||
      std::strcmp(fields[0], session->proof) != 0 ||
      (std::strcmp(fields[1], "request") && std::strcmp(fields[1], "choosePrivateKey") &&
       std::strcmp(fields[1], "saveFirewallScript"))) {
    webkit_script_message_reply_return_error_message(message, "Invalid desktop message");
  } else if (session->pending >= 16) {
    webkit_script_message_reply_return_error_message(message, "Too many desktop requests");
  } else {
    auto *reply = new Reply{session, webkit_script_message_reply_ref(message),
                            JSC_CONTEXT(g_object_ref(jsc_value_get_context(value))), nullptr, nullptr, nullptr, nullptr};
    ++session->pending;
    if (!std::strcmp(fields[1], "choosePrivateKey")) chooser(reply);
    else desktopGTKMessage(session->handle, reinterpret_cast<uintptr_t>(reply), fields[1], fields[2]);
  }
  g_strfreev(fields);
  g_free(body);
  return TRUE;
}

void close_window(GtkWidget *, gpointer data) {
  auto *session = static_cast<Session *>(data);
  session->closed = true;
  desktopGTKCancel(session->handle);
  while (session->choosers) {
    auto *reply = static_cast<Reply *>(session->choosers->data);
    choose_response(GTK_NATIVE_DIALOG(reply->chooser), GTK_RESPONSE_CANCEL, reply);
  }
}

gboolean load_failed(WebKitWebView *, WebKitLoadEvent, const char *uri, GError *error, gpointer data) {
  auto *session = static_cast<Session *>(data);
  if (!session->closed && asset_index(uri, true) == 0 &&
      !g_error_matches(error, WEBKIT_NETWORK_ERROR, WEBKIT_NETWORK_ERROR_CANCELLED)) {
    session->failure = -3;
    gtk_widget_destroy(GTK_WIDGET(session->window));
    return TRUE;
  }
  return FALSE;
}
} // namespace

int infra_gtk_run(uintptr_t handle, const char *proof, const void *index, size_t index_length,
                  const void *style, size_t style_length, const void *script, size_t script_length) {
  webview_t webview = webview_create(0, nullptr);
  if (!webview) return -1;
  auto *view = WEBKIT_WEB_VIEW(webview_get_native_handle(webview, WEBVIEW_NATIVE_HANDLE_KIND_BROWSER_CONTROLLER));
  auto *window = GTK_WINDOW(webview_get_native_handle(webview, WEBVIEW_NATIVE_HANDLE_KIND_UI_WINDOW));
  if (!view || !window) {
    webview_destroy(webview);
    return -1;
  }
  Session session{handle, proof, {g_bytes_new(index, index_length), g_bytes_new(style, style_length),
                                  g_bytes_new(script, script_length)}, view, window, nullptr, 0, 0, false};
  current = &session;
  WebKitWebContext *context = webkit_web_view_get_context(view);
  if (!g_object_get_data(G_OBJECT(context), "imon-scheme-registered")) {
    webkit_web_context_register_uri_scheme(context, scheme, scheme_request, nullptr, nullptr);
    g_object_set_data(G_OBJECT(context), "imon-scheme-registered", GINT_TO_POINTER(1));
  }
  WebKitSecurityManager *security = webkit_web_context_get_security_manager(context);
  webkit_security_manager_register_uri_scheme_as_secure(security, scheme);
  webkit_security_manager_register_uri_scheme_as_cors_enabled(security, scheme);
  webkit_web_context_set_cache_model(context, WEBKIT_CACHE_MODEL_DOCUMENT_VIEWER);
  auto *manager = webkit_web_view_get_user_content_manager(view);
  webkit_user_content_manager_unregister_script_message_handler(manager, "__webview__");
  webkit_user_content_manager_remove_all_scripts(manager);
  g_signal_connect(manager, "script-message-with-reply-received::imonNative", G_CALLBACK(bridge_message), &session);
  g_signal_connect(view, "decide-policy", G_CALLBACK(decide_policy), &session);
  g_signal_connect(view, "load-failed", G_CALLBACK(load_failed), &session);
  g_signal_connect(window, "destroy", G_CALLBACK(close_window), &session);
  if (!webkit_user_content_manager_register_script_message_handler_with_reply(manager, bridge, nullptr)) {
    session.failure = -2;
    gtk_widget_destroy(GTK_WIDGET(window));
  } else {
    // The reply-capable GTK handler does not return frame identity to native
    // code. Only the local top-frame closure receives this session proof.
    gchar *init = g_strdup_printf(
      "(() => {"
        "if (location.protocol !== 'imon:' || location.host !== 'panel' || location.pathname !== '/' || window.top !== window) return;"
        "const send = window.webkit.messageHandlers.imonNative.postMessage;"
        "const native = window.webkit.messageHandlers.imonNative;"
        "const invoke = (op, value) => send.call(native, '%s\\n' + op + '\\n' + JSON.stringify(value));"
        "Object.defineProperty(window, 'imonDesktop', {value: Object.freeze({"
          "request: (value) => invoke('request', value),"
          "choosePrivateKey: () => invoke('choosePrivateKey', {}),"
          "saveFirewallScript: (value) => invoke('saveFirewallScript', value)"
        "})});"
      "})();", proof);
    WebKitUserScript *injected = webkit_user_script_new(init, WEBKIT_USER_CONTENT_INJECT_TOP_FRAME,
      WEBKIT_USER_SCRIPT_INJECT_AT_DOCUMENT_START, nullptr, nullptr);
    webkit_user_content_manager_add_script(manager, injected);
    webkit_user_script_unref(injected);
    g_free(init);
    webview_set_title(webview, "Imon");
    webview_set_size(webview, 1200, 800, WEBVIEW_HINT_NONE);
    const int navigation = webview_navigate(webview, app_url);
    if (navigation == WEBVIEW_ERROR_OK) webview_run(webview);
    else {
      session.failure = navigation;
      gtk_widget_destroy(GTK_WIDGET(window));
    }
  }
  if (!session.closed) gtk_widget_destroy(GTK_WIDGET(window));
  while (session.pending) g_main_context_iteration(nullptr, TRUE);
  webkit_user_content_manager_unregister_script_message_handler(manager, bridge);
  g_signal_handlers_disconnect_by_data(manager, &session);
  g_signal_handlers_disconnect_by_data(view, &session);
  current = nullptr;
  webview_destroy(webview);
  for (auto *asset : session.assets) g_bytes_unref(asset);
  return session.failure;
}

void infra_gtk_stop(uintptr_t handle) {
  g_idle_add(+[](gpointer token) -> gboolean {
    if (current && current->handle == reinterpret_cast<uintptr_t>(token) && !current->closed)
      gtk_widget_destroy(GTK_WIDGET(current->window));
    return G_SOURCE_REMOVE;
  }, reinterpret_cast<gpointer>(handle));
}

void infra_gtk_alert(const char *error) {
  if (!gtk_init_check(nullptr, nullptr)) return;
  GtkWidget *dialog = gtk_message_dialog_new(nullptr, GTK_DIALOG_MODAL, GTK_MESSAGE_ERROR, GTK_BUTTONS_CLOSE, "%s", error);
  gtk_dialog_run(GTK_DIALOG(dialog));
  gtk_widget_destroy(dialog);
}

void infra_gtk_reply(uintptr_t raw, const char *json, const char *error) {
  auto *reply = reinterpret_cast<Reply *>(raw);
  reply->json = g_strdup(json);
  reply->error = g_strdup(error);
  g_idle_add(+[](gpointer data) -> gboolean {
    auto *reply = static_cast<Reply *>(data);
    JSCValue *value = !reply->session->closed && reply->json ? jsc_value_new_from_json(reply->context, reply->json) : nullptr;
    finish(reply, value, reply->error ? reply->error : value ? nullptr : "Invalid desktop response");
    return G_SOURCE_REMOVE;
  }, reply);
}

void infra_gtk_save(uintptr_t raw, const void *bytes, size_t length) {
  auto *reply = reinterpret_cast<Reply *>(raw);
  reply->script = g_bytes_new(bytes, length);
  g_idle_add(+[](gpointer data) -> gboolean {
    chooser(static_cast<Reply *>(data));
    return G_SOURCE_REMOVE;
  }, reply);
}
