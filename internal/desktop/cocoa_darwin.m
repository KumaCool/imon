#include "cocoa_darwin.h"
#include "vendor/webview.h"
#import <Cocoa/Cocoa.h>
#import <WebKit/WebKit.h>

extern void desktopMessage(uintptr_t state, uintptr_t reply, char *operation, char *json);

static NSString *const Scheme = @"imon";
static NSString *const Host = @"app";
static NSString *const BridgeName = @"imonNative";
static NSString *const AppURL = @"imon://app/";

typedef void (^Reply)(id, NSString *);

static BOOL localOrigin(NSURL *url) {
    return [url.scheme isEqualToString:Scheme] && [url.host isEqualToString:Host] &&
           !url.port && !url.user && !url.password;
}

static BOOL trustedDocument(NSURL *url) {
    return localOrigin(url) && [url.path isEqualToString:@"/"] && !url.query;
}

static BOOL openExternal(WKNavigationAction *action) {
    NSURL *url = action.request.URL;
    if (action.sourceFrame.isMainFrame &&
        trustedDocument(action.sourceFrame.request.URL) &&
        action.navigationType == WKNavigationTypeLinkActivated &&
        [url.scheme isEqualToString:@"https"] && url.host.length && !url.user && !url.password) {
        return [NSWorkspace.sharedWorkspace openURL:url];
    }
    return NO;
}

static NSMenu *desktopMenu(NSWindow *window) {
    NSMenu *menu = [[[NSMenu alloc] initWithTitle:@""] autorelease];
    NSMenuItem *appItem = [menu addItemWithTitle:@"Imon" action:NULL keyEquivalent:@""];
    appItem.submenu = [[[NSMenu alloc] initWithTitle:@"Imon"] autorelease];
    NSMenuItem *quit = [appItem.submenu addItemWithTitle:@"退出 Imon" action:@selector(performClose:) keyEquivalent:@"q"];
    quit.target = window;

    // Leave targets nil so AppKit routes each action to the focused responder.
    NSMenuItem *editItem = [menu addItemWithTitle:@"编辑" action:NULL keyEquivalent:@""];
    editItem.submenu = [[[NSMenu alloc] initWithTitle:@"编辑"] autorelease];
    [editItem.submenu addItemWithTitle:@"剪切" action:@selector(cut:) keyEquivalent:@"x"];
    [editItem.submenu addItemWithTitle:@"复制" action:@selector(copy:) keyEquivalent:@"c"];
    [editItem.submenu addItemWithTitle:@"粘贴" action:@selector(paste:) keyEquivalent:@"v"];
    [editItem.submenu addItemWithTitle:@"全选" action:@selector(selectAll:) keyEquivalent:@"a"];
    return menu;
}

@interface DesktopSession : NSObject <WKURLSchemeHandler, WKNavigationDelegate, WKUIDelegate, WKScriptMessageHandlerWithReply> {
@public
    uintptr_t state;
    WKWebView *view;
    id<WKUIDelegate> oldUIDelegate;
    NSDictionary<NSString *, NSData *> *assets;
    BOOL closed;
    BOOL stopping;
}
@end

static DesktopSession *session;

@implementation DesktopSession
- (void)webView:(WKWebView *)webView startURLSchemeTask:(id<WKURLSchemeTask>)task {
    NSURL *url = task.request.URL;
    NSData *body = localOrigin(url) && !url.query &&
                   [task.request.HTTPMethod isEqualToString:@"GET"] ? assets[url.path ?: @""] : nil;
    if (!body) {
        [task didFailWithError:[NSError errorWithDomain:NSURLErrorDomain code:NSURLErrorResourceUnavailable userInfo:nil]];
        return;
    }
    NSString *type = @"text/html; charset=utf-8";
    if ([url.path isEqualToString:@"/app.css"]) type = @"text/css; charset=utf-8";
    if ([url.path isEqualToString:@"/app.js"]) type = @"text/javascript; charset=utf-8";
    NSDictionary *headers = @{
        @"Content-Type": type,
        @"X-Content-Type-Options": @"nosniff",
        @"Content-Security-Policy": @"default-src 'none'; script-src imon:; style-src imon: 'unsafe-inline'; img-src imon: data:; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
    };
    NSHTTPURLResponse *response = [[[NSHTTPURLResponse alloc] initWithURL:url statusCode:200 HTTPVersion:@"HTTP/1.1" headerFields:headers] autorelease];
    [task didReceiveResponse:response];
    [task didReceiveData:body];
    [task didFinish];
}
- (void)webView:(WKWebView *)webView stopURLSchemeTask:(id<WKURLSchemeTask>)task {}

- (void)webView:(WKWebView *)webView decidePolicyForNavigationAction:(WKNavigationAction *)action
decisionHandler:(void (^)(WKNavigationActionPolicy))decision {
    if (action.targetFrame.isMainFrame && trustedDocument(action.request.URL)) {
        decision(WKNavigationActionPolicyAllow);
        return;
    }
    if (action.targetFrame) openExternal(action);
    decision(WKNavigationActionPolicyCancel);
}

- (WKWebView *)webView:(WKWebView *)webView createWebViewWithConfiguration:(WKWebViewConfiguration *)config
  forNavigationAction:(WKNavigationAction *)action windowFeatures:(WKWindowFeatures *)features {
    openExternal(action);
    return nil;
}

- (BOOL)respondsToSelector:(SEL)aSelector {
    return [super respondsToSelector:aSelector] || [oldUIDelegate respondsToSelector:aSelector];
}

- (id)forwardingTargetForSelector:(SEL)aSelector {
    return [oldUIDelegate respondsToSelector:aSelector] ? oldUIDelegate : [super forwardingTargetForSelector:aSelector];
}

- (void)userContentController:(WKUserContentController *)controller didReceiveScriptMessage:(WKScriptMessage *)message
                 replyHandler:(Reply)reply {
    if (closed || message.webView != view || !message.frameInfo.isMainFrame || !trustedDocument(message.frameInfo.request.URL)) {
        reply(nil, @"Untrusted desktop document");
        return;
    }
    if (![message.body isKindOfClass:NSDictionary.class]) {
        reply(nil, @"Invalid desktop message");
        return;
    }
    NSString *operation = message.body[@"operation"];
    NSString *json = message.body[@"payload"];
    if (![operation isKindOfClass:NSString.class] || operation.length > 32 || ![json isKindOfClass:NSString.class] ||
        [json lengthOfBytesUsingEncoding:NSUTF8StringEncoding] > 1024 * 1024) {
        reply(nil, @"Invalid desktop message");
        return;
    }
    if ([operation isEqualToString:@"choosePrivateKey"]) {
        NSOpenPanel *panel = NSOpenPanel.openPanel;
        panel.canChooseFiles = YES;
        panel.canChooseDirectories = NO;
        panel.allowsMultipleSelection = NO;
        panel.showsHiddenFiles = YES;
        [panel beginSheetModalForWindow:view.window completionHandler:^(NSModalResponse result) {
            if (result == NSModalResponseOK && panel.URL.path)
                reply(@{@"path": panel.URL.path, @"canceled": @NO}, nil);
            else
                reply(@{@"path": @"", @"canceled": @YES}, nil);
        }];
        return;
    }
    desktopMessage(state, (uintptr_t)[reply copy], (char *)operation.UTF8String, (char *)json.UTF8String);
}
- (void)dealloc {
    [assets release];
    [super dealloc];
}
@end

void infra_desktop_configure_cocoa(void *raw) {
    WKWebViewConfiguration *config = (WKWebViewConfiguration *)raw;
    config.websiteDataStore = WKWebsiteDataStore.nonPersistentDataStore;
    [config setURLSchemeHandler:session forURLScheme:Scheme];
}

// Installed before navigation; WebKit supplies trusted frame identity on every call.
static NSString *const InitJS =
    @"(() => {"
      "const native = window.webkit.messageHandlers.imonNative;"
      "const invoke = (operation, payload) => native.postMessage({operation,payload:JSON.stringify(payload)});"
      "Object.defineProperty(window,'imonDesktop',{value:Object.freeze({"
        "request:(value)=>invoke('request',value),"
        "choosePrivateKey:()=>invoke('choosePrivateKey',{}),"
        "saveFirewallScript:(value)=>invoke('saveFirewallScript',value)"
      "})});"
    "})();";

int infra_desktop_run(uintptr_t goState, const char *index, size_t indexSize,
                      const char *style, size_t styleSize, const char *script,
                      size_t scriptSize) {
    @autoreleasepool {
        session = [DesktopSession new];
        session->state = goState;
        session->assets = [@{
            @"/": [NSData dataWithBytes:index length:indexSize],
            @"/app.css": [NSData dataWithBytes:style length:styleSize],
            @"/app.js": [NSData dataWithBytes:script length:scriptSize],
        } retain];
        webview_t w = webview_create(0, NULL);
        if (!w) {
            [session release];
            session = nil;
            return -1;
        }
        WKWebView *view = (WKWebView *)webview_get_native_handle(w, WEBVIEW_NATIVE_HANDLE_KIND_BROWSER_CONTROLLER);
        int result = -1;
        if (view) {
            session->view = [view retain];
            session->oldUIDelegate = view.UIDelegate;
            view.navigationDelegate = session;
            view.UIDelegate = session;
            WKUserContentController *content = view.configuration.userContentController;
            [content removeScriptMessageHandlerForName:@"__webview__"];
            [content removeAllUserScripts];
            [content addScriptMessageHandlerWithReply:session contentWorld:WKContentWorld.pageWorld name:BridgeName];
            WKUserScript *script = [[[WKUserScript alloc] initWithSource:InitJS
                                           injectionTime:WKUserScriptInjectionTimeAtDocumentStart
                                         forMainFrameOnly:YES] autorelease];
            [content addUserScript:script];
            webview_set_title(w, "Imon");
            webview_set_size(w, 1200, 800, WEBVIEW_HINT_NONE);
            NSMenu *previousMenu = [NSApp.mainMenu retain];
            NSApp.mainMenu = desktopMenu(view.window);
            if (session->stopping) {
                result = WEBVIEW_ERROR_OK;
            } else if (webview_navigate(w, AppURL.UTF8String) == WEBVIEW_ERROR_OK) {
                result = webview_run(w);
            }
            session->closed = YES;
            [content removeScriptMessageHandlerForName:BridgeName contentWorld:WKContentWorld.pageWorld];
            view.navigationDelegate = nil;
            view.UIDelegate = session->oldUIDelegate;
            [view stopLoading];
            [view release];
            session->view = nil;
            NSApp.mainMenu = previousMenu;
            [previousMenu release];
        }
        webview_destroy(w);
        [session release];
        session = nil;
        return result;
    }
}

void infra_desktop_stop(void) {
    dispatch_async(dispatch_get_main_queue(), ^{
        if (session && !session->closed) {
            session->stopping = YES;
            [session->view.window close];
        }
    });
}

void infra_desktop_alert(const char *error) {
    @autoreleasepool {
        [NSApplication sharedApplication];
        [NSApp setActivationPolicy:NSApplicationActivationPolicyRegular];
        [NSApp activateIgnoringOtherApps:YES];
        NSAlert *alert = [[[NSAlert alloc] init] autorelease];
        alert.messageText = @"Imon";
        alert.informativeText = [NSString stringWithUTF8String:error];
        alert.alertStyle = NSAlertStyleCritical;
        [alert runModal];
    }
}

void infra_desktop_reply(uintptr_t raw, const char *json, const char *error) {
    @autoreleasepool {
        Reply reply = (Reply)raw;
        NSString *problem = error ? [NSString stringWithUTF8String:error] : nil;
        id response = json ? [NSJSONSerialization JSONObjectWithData:
                              [NSData dataWithBytes:json length:strlen(json)]
                              options:0 error:NULL] : nil;
        if (!problem && !response) problem = @"Invalid desktop response";
        dispatch_async(dispatch_get_main_queue(), ^{ reply(response, problem); });
        [reply release];
    }
}

void infra_desktop_save(uintptr_t raw, const char *data, size_t size) {
    @autoreleasepool {
        Reply reply = (Reply)raw;
        NSData *bytes = [NSData dataWithBytes:data length:size];
        dispatch_async(dispatch_get_main_queue(), ^{
            if (!session || session->closed || !session->view.window) {
                reply(nil, @"Desktop window is closed");
                return;
            }
            NSSavePanel *panel = NSSavePanel.savePanel;
            panel.nameFieldStringValue = @"firewall-maintain.sh";
            [panel beginSheetModalForWindow:session->view.window completionHandler:^(NSModalResponse result) {
                if (result != NSModalResponseOK || !panel.URL) {
                    reply(@{@"saved": @NO, @"canceled": @YES}, nil);
                    return;
                }
                if (![bytes writeToURL:panel.URL options:NSDataWritingAtomic error:NULL]) {
                    reply(nil, @"Could not save the firewall script");
                    return;
                }
                reply(@{@"saved": @YES, @"canceled": @NO}, nil);
            }];
        });
        [reply release];
    }
}
