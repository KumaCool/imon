//go:build windows && amd64 && cgo && desktop

#include "webview2_windows.h"
#include "windows_icon.h"
#define WEBVIEW_STATIC
#include "vendor/webview.h"
#include <commdlg.h>
#include <shellapi.h>
#include <mutex>
#include <memory>

extern "C" void infraWindowsMessage(uintptr_t, char *, size_t);

namespace {
constexpr wchar_t origin[] = L"https://imon.invalid/";
constexpr wchar_t csp[] = L"\r\nContent-Security-Policy: default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'none'\r\nX-Content-Type-Options: nosniff";
constexpr IID env_iid{0x9e8f0cf8,0xe670,0x4b5e,{0xb2,0xbc,0x73,0xe0,0x61,0xe3,0x18,0x4c}};
constexpr IID message_iid{0x57213f19,0x00e6,0x49fa,{0x8e,0x07,0x89,0x8e,0xa0,0x1e,0xcb,0xd2}};
constexpr IID nav_iid{0x9adbe429,0xf36d,0x432b,{0x9d,0xdc,0xf8,0x88,0x1f,0xbd,0x76,0xe3}};
constexpr IID new_iid{0xd4c185fe,0xc81c,0x4989,{0x97,0xaf,0x2d,0x3f,0xa7,0xab,0x56,0x51}};
constexpr IID resource_iid{0xab00b74c,0x15f1,0x4646,{0x80,0xe8,0xe7,0x63,0x41,0xd2,0x5d,0x71}};
constexpr IID script_iid{0xb99369f3,0x9b11,0x47b5,{0xbc,0x6f,0x8e,0x78,0x95,0xfc,0xea,0x17}};

template<class T> struct Release {
  void operator()(T *ptr) const { if (ptr) ptr->Release(); }
};
template<class T> using Com = std::unique_ptr<T,Release<T>>;

template<class Handler, class... Args> class Callback final : public Handler {
  std::atomic<ULONG> refs{1};
  const IID &id;
  std::function<HRESULT(Args...)> fn;
public:
  Callback(const IID &iid, std::function<HRESULT(Args...)> f) : id(iid), fn(std::move(f)) {}
  HRESULT STDMETHODCALLTYPE QueryInterface(REFIID iid, void **obj) override {
    if (!obj) return E_POINTER;
    *obj = nullptr;
    if (iid != IID_IUnknown && iid != id) return E_NOINTERFACE;
    *obj = static_cast<Handler *>(this);
    AddRef();
    return S_OK;
  }
  ULONG STDMETHODCALLTYPE AddRef() override { return ++refs; }
  ULONG STDMETHODCALLTYPE Release() override {
    ULONG n = --refs;
    if (!n) delete this;
    return n;
  }
  HRESULT STDMETHODCALLTYPE Invoke(Args... args) override {
    try { return fn(args...); } catch (...) { return E_FAIL; }
  }
};

template<class Interface, class... Args, class F>
Com<Interface> handler(const IID &iid, F f) {
  return Com<Interface>(new Callback<Interface, Args...>(iid, std::move(f)));
}
bool prefix(const std::wstring &s, const std::wstring &p) { return s.compare(0,p.size(),p) == 0; }
bool trusted(const std::wstring &u) { return u == origin || prefix(u,std::wstring(origin)+L"#"); }

std::wstring wide(const std::string &s) {
  if (s.empty()) return {};
  int n = MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,s.data(),int(s.size()),nullptr,0);
  std::wstring result(n,L'\0');
  if (n) MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,s.data(),int(s.size()),result.data(),n);
  return result;
}
std::string utf8(const std::wstring &s) {
  if (s.empty()) return {};
  int n = WideCharToMultiByte(CP_UTF8,WC_ERR_INVALID_CHARS,s.data(),int(s.size()),nullptr,0,nullptr,nullptr);
  std::string result(n,'\0');
  if (n) WideCharToMultiByte(CP_UTF8,WC_ERR_INVALID_CHARS,s.data(),int(s.size()),result.data(),n,nullptr,nullptr);
  return result;
}
std::wstring take(LPWSTR p) {
  std::wstring value = p ? p : L"";
  CoTaskMemFree(p);
  return value;
}
std::string quote(const std::string &s) {
  std::string out = "\"";
  static const char hex[] = "0123456789abcdef";
  for (unsigned char ch : s) {
    if (ch == '"' || ch == '\\') { out += '\\'; out += ch; }
    else if (ch < 32) { out += "\\u00"; out += hex[ch >> 4]; out += hex[ch & 15]; }
    else out += ch;
  }
  return out + "\"";
}

struct Session {
  webview_t window{};
  HWND hwnd{};
  HICON big_icon{}, small_icon{};
  Com<ICoreWebView2> view;
  Com<ICoreWebView2Environment> env;
  uintptr_t handle{};
  std::map<std::wstring, std::pair<std::string,std::wstring>> assets;
  std::wstring script;
  EventRegistrationToken nav{},frame{},popup{},resource{},received{};
  bool nav_set{},frame_set{},popup_set{},resource_set{},received_set{},filter_set{};
  bool dialog{};
  ~Session() {
    if (view) {
      if (received_set) view->remove_WebMessageReceived(received);
      if (resource_set) view->remove_WebResourceRequested(resource);
      if (filter_set) view->RemoveWebResourceRequestedFilter(L"*",COREWEBVIEW2_WEB_RESOURCE_CONTEXT_ALL);
      if (popup_set) view->remove_NewWindowRequested(popup);
      if (frame_set) view->remove_FrameNavigationStarting(frame);
      if (nav_set) view->remove_NavigationStarting(nav);
      if (!script.empty()) view->RemoveScriptToExecuteOnDocumentCreated(script.c_str());
      view.reset();
    }
    if (window) webview_destroy(window);
    if (big_icon) DestroyIcon(big_icon);
    if (small_icon) DestroyIcon(small_icon);
  }
};
std::mutex active_lock;
Session *active;
bool stopped;

void external(const std::wstring &u) {
  if (prefix(u,L"https://") && !prefix(u,origin))
    ShellExecuteW(nullptr,L"open",u.c_str(),nullptr,nullptr,SW_SHOWNORMAL);
}

std::wstring init_script(const char *proof) {
  return wide(std::string(R"JS(
(() => {
  if (window !== window.top || location.origin !== 'https://imon.invalid' ||
      location.pathname !== '/' || location.search) return;
  const native = window.chrome.webview;
  const pending = new Map();
  const proof = ')JS")+proof+R"JS(';
  native.addEventListener('message', ({data}) => {
    const entry = pending.get(data?.call);
    if (!entry) return;
    pending.delete(data.call);
    data.error ? entry.reject(new Error(data.error)) : entry.resolve(data.result);
  });
  const invoke = (op, payload) => new Promise((resolve,reject) => {
    const call = crypto.randomUUID();
    pending.set(call,{resolve,reject});
    try { native.postMessage({proof,call,op,payload}); }
    catch (error) { pending.delete(call); reject(error); }
  });
  Object.defineProperty(window,'imonDesktop',{value:Object.freeze({
    request:(value)=>invoke('request',value),
    choosePrivateKey:()=>invoke('choosePrivateKey',{}),
    saveFirewallScript:(value)=>invoke('saveFirewallScript',value)
  })});
})();
)JS");
}

HRESULT attach(Session &s) {
  auto *v = s.view.get();
  ICoreWebView2_2 *v2{};
  HRESULT hr = v->QueryInterface(env_iid,reinterpret_cast<void **>(&v2));
  if (FAILED(hr)) return hr;
  Com<ICoreWebView2_2> v2ref(v2);
  ICoreWebView2Environment *env{};
  if (FAILED(hr=v2->get_Environment(&env))) return hr;
  s.env.reset(env);

  auto navigation = handler<ICoreWebView2NavigationStartingEventHandler,ICoreWebView2 *,ICoreWebView2NavigationStartingEventArgs *>(nav_iid,
    [](auto*,auto* e) {
      LPWSTR raw{};
      if (FAILED(e->get_Uri(&raw))) return e->put_Cancel(TRUE);
      const auto uri = take(raw);
      if (trusted(uri)) return S_OK;
      e->put_Cancel(TRUE);
      BOOL initiated{};
      if (SUCCEEDED(e->get_IsUserInitiated(&initiated)) && initiated) external(uri);
      return S_OK;
    });
  if (FAILED(hr=v->add_NavigationStarting(navigation.get(),&s.nav))) return hr;
  s.nav_set = true;
  auto frame = handler<ICoreWebView2NavigationStartingEventHandler,ICoreWebView2 *,ICoreWebView2NavigationStartingEventArgs *>(nav_iid,
    [](auto*,auto* e){ return e->put_Cancel(TRUE); });
  if (FAILED(hr=v->add_FrameNavigationStarting(frame.get(),&s.frame))) return hr;
  s.frame_set = true;
  auto popup = handler<ICoreWebView2NewWindowRequestedEventHandler,ICoreWebView2 *,ICoreWebView2NewWindowRequestedEventArgs *>(new_iid,
    [](auto*,auto* e){
      e->put_Handled(TRUE);
      BOOL initiated{};
      LPWSTR raw{};
      if (SUCCEEDED(e->get_IsUserInitiated(&initiated)) && initiated && SUCCEEDED(e->get_Uri(&raw))) external(take(raw));
      return S_OK;
    });
  if (FAILED(hr=v->add_NewWindowRequested(popup.get(),&s.popup))) return hr;
  s.popup_set = true;

  if (FAILED(hr=v->AddWebResourceRequestedFilter(L"*",COREWEBVIEW2_WEB_RESOURCE_CONTEXT_ALL))) return hr;
  s.filter_set = true;
  auto resource = handler<ICoreWebView2WebResourceRequestedEventHandler,ICoreWebView2 *,ICoreWebView2WebResourceRequestedEventArgs *>(resource_iid,
    [&s](auto*,auto* e){
      ICoreWebView2WebResourceRequest *raw{};
      if (FAILED(e->get_Request(&raw))) return E_FAIL;
      Com<ICoreWebView2WebResourceRequest> req(raw);
      LPWSTR uri{}, method{};
      req->get_Uri(&uri);
      req->get_Method(&method);
      auto url = take(uri);
      const auto hash = url.find(L'#');
      if (hash != std::wstring::npos) url.resize(hash);
      const auto item = s.assets.find(url);
      const bool get = take(method)==L"GET";
      const bool valid = item != s.assets.end() && get;
      Com<IStream> stream;
      std::wstring headers = L"Content-Type: text/plain; charset=utf-8";
      if (valid) {
        const auto &asset = item->second;
        stream.reset(SHCreateMemStream(reinterpret_cast<const BYTE *>(asset.first.data()),UINT(asset.first.size())));
        if (!stream) return E_OUTOFMEMORY;
        headers = L"Content-Type: "+asset.second+csp;
      }
      ICoreWebView2WebResourceResponse *raw_response{};
      HRESULT result = s.env->CreateWebResourceResponse(stream.get(),valid?200:404,valid?L"OK":L"Not Found",headers.c_str(),&raw_response);
      if (FAILED(result)) return result;
      Com<ICoreWebView2WebResourceResponse> response(raw_response);
      return e->put_Response(response.get());
    });
  if (FAILED(hr=v->add_WebResourceRequested(resource.get(),&s.resource))) return hr;
  s.resource_set = true;

  auto messages = handler<ICoreWebView2WebMessageReceivedEventHandler,ICoreWebView2 *,ICoreWebView2WebMessageReceivedEventArgs *>(message_iid,
    [&s](auto*,auto* e){
      LPWSTR raw{};
      if (FAILED(e->get_Source(&raw)) || !trusted(take(raw))) return S_OK;
      raw=nullptr;
      if (FAILED(e->get_WebMessageAsJson(&raw))) return S_OK;
      auto json = take(raw);
      if (json.size() > (1u<<20)+4096) return S_OK;
      auto bytes = utf8(json);
      infraWindowsMessage(s.handle,bytes.data(),bytes.size());
      return S_OK;
    });
  if (FAILED(hr=v->add_WebMessageReceived(messages.get(),&s.received))) return hr;
  s.received_set = true;
  return S_OK;
}

using Action = std::function<void(Session &)>;
void dispatch(Action action) {
  std::lock_guard<std::mutex> l(active_lock);
  if (!active) return;
  auto *job = new Action(std::move(action));
  if (webview_dispatch(active->window,[](webview_t window,void *raw) {
    std::unique_ptr<Action> task(static_cast<Action *>(raw));
    Session *s{};
    {
      std::lock_guard<std::mutex> l(active_lock);
      if (active && active->window==window) s=active;
    }
    if (s) (*task)(*s);
  },job)!=WEBVIEW_ERROR_OK) delete job;
}
void answer(Session &s,const std::string &id,const std::string &result) {
  LPWSTR src{};
  if (FAILED(s.view->get_Source(&src)) || !trusted(take(src))) return;
  if (result.size()<2 || result[0]!='{') return;
  auto message = wide("{\"call\":"+quote(id)+","+result.substr(1));
  s.view->PostWebMessageAsJson(message.c_str());
}

std::wstring file_dialog(HWND owner,bool save,DWORD &error) {
  std::wstring file(32768,L'\0');
  if (save) wcsncpy(file.data(),L"firewall-maintain.sh",file.size()-1);
  OPENFILENAMEW dlg{};
  dlg.lStructSize=sizeof(dlg);
  dlg.hwndOwner=owner;
  dlg.lpstrFile=file.data();
  dlg.nMaxFile=DWORD(file.size());
  dlg.lpstrFilter=save?L"Shell script (*.sh)\0*.sh\0All files\0*.*\0":L"All files\0*.*\0";
  dlg.lpstrDefExt=save?L"sh":nullptr;
  dlg.Flags=OFN_EXPLORER | OFN_NOCHANGEDIR | OFN_PATHMUSTEXIST | (save?OFN_OVERWRITEPROMPT:OFN_FILEMUSTEXIST);
  if (!(save?GetSaveFileNameW(&dlg):GetOpenFileNameW(&dlg))) {
    error=CommDlgExtendedError();
    return {};
  }
  file.resize(wcslen(file.c_str()));
  return file;
}
bool write_file(const std::wstring &path,const std::string &data,const std::string &id) {
  std::wstring temp=path+L"."+wide(id)+L".tmp";
  HANDLE file=CreateFileW(temp.c_str(),GENERIC_WRITE,0,nullptr,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,nullptr);
  if (file==INVALID_HANDLE_VALUE) return false;
  DWORD written{};
  bool ok=WriteFile(file,data.data(),DWORD(data.size()),&written,nullptr) && written==data.size();
  ok=CloseHandle(file) && ok;
  if (ok && MoveFileExW(temp.c_str(),path.c_str(),MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) return true;
  DeleteFileW(temp.c_str());
  return false;
}
}

extern "C" int infra_windows_run(uintptr_t id,const char *proof,const char *html,size_t nh,const char *css,size_t nc,const char *js,size_t nj) {
  Session s;
  s.handle=id;
  s.assets.emplace(origin,std::make_pair(std::string(html,nh),L"text/html; charset=utf-8"));
  s.assets.emplace(std::wstring(origin)+L"app.css",std::make_pair(std::string(css,nc),L"text/css; charset=utf-8"));
  s.assets.emplace(std::wstring(origin)+L"app.js",std::make_pair(std::string(js,nj),L"text/javascript; charset=utf-8"));
  s.window=webview_create(0,nullptr);
  if (!s.window) return -1;
  s.hwnd=static_cast<HWND>(webview_get_window(s.window));
  HMODULE executable=GetModuleHandleW(nullptr);
  s.big_icon=static_cast<HICON>(LoadImageW(executable,MAKEINTRESOURCEW(IMON_APP_ICON),IMAGE_ICON,
    GetSystemMetrics(SM_CXICON),GetSystemMetrics(SM_CYICON),0));
  s.small_icon=static_cast<HICON>(LoadImageW(executable,MAKEINTRESOURCEW(IMON_APP_ICON),IMAGE_ICON,
    GetSystemMetrics(SM_CXSMICON),GetSystemMetrics(SM_CYSMICON),0));
  if (s.big_icon) SendMessageW(s.hwnd,WM_SETICON,ICON_BIG,reinterpret_cast<LPARAM>(s.big_icon));
  if (s.small_icon) SendMessageW(s.hwnd,WM_SETICON,ICON_SMALL,reinterpret_cast<LPARAM>(s.small_icon));
  auto *controller=static_cast<ICoreWebView2Controller *>(webview_get_native_handle(s.window,WEBVIEW_NATIVE_HANDLE_KIND_BROWSER_CONTROLLER));
  ICoreWebView2 *view{};
  if (!controller || FAILED(controller->get_CoreWebView2(&view)) || !view) return -2;
  s.view.reset(view);
  if (FAILED(attach(s))) return -3;
  auto script=init_script(proof);
  struct ScriptRegistration { HRESULT result{E_PENDING}; std::wstring identifier; };
  auto established=std::make_shared<ScriptRegistration>();
  auto complete=handler<ICoreWebView2AddScriptToExecuteOnDocumentCreatedCompletedHandler,HRESULT,LPCWSTR>(script_iid,
    [established](HRESULT hr,LPCWSTR identifier){
      if (SUCCEEDED(hr) && identifier) established->identifier=identifier;
      established->result=hr;
      return S_OK;
    });
  if (FAILED(view->AddScriptToExecuteOnDocumentCreated(script.c_str(),complete.get()))) return -4;
  // The initialization callback is delivered on the STA before navigation begins.
  MSG msg;
  while (established->result==E_PENDING && GetMessageW(&msg,nullptr,0,0)>0) {
    TranslateMessage(&msg);
    DispatchMessageW(&msg);
  }
  if (FAILED(established->result)) return -4;
  s.script=std::move(established->identifier);
  webview_set_title(s.window,"Imon");
  webview_set_size(s.window,1200,800,WEBVIEW_HINT_NONE);
  {
    std::lock_guard<std::mutex> l(active_lock);
    if (stopped) return 0;
    active=&s;
  }
  int result=-5;
  if (SUCCEEDED(view->Navigate(origin))) {
    result=webview_run(s.window);
  }
  {
    std::lock_guard<std::mutex> l(active_lock);
    active=nullptr;
  }
  return result;
}

extern "C" void infra_windows_stop() {
  std::lock_guard<std::mutex> l(active_lock);
  stopped=true;
  if (active) PostMessageW(active->hwnd,WM_CLOSE,0,0);
}
extern "C" void infra_windows_alert(const char *message) {
  MessageBoxW(nullptr,wide(message).c_str(),L"Imon",MB_OK|MB_ICONERROR);
}
extern "C" void infra_windows_reply(const char *id,const char *data,size_t n) {
  dispatch([id=std::string(id),result=std::string(data,n)](Session &s){ answer(s,id,result); });
}
extern "C" void infra_windows_choose(const char *id) {
  dispatch([id=std::string(id)](Session &s){
    if (s.dialog) { answer(s,id,"{\"error\":\"Another file dialog is open\"}"); return; }
    s.dialog=true;
    DWORD error{};
    auto path=file_dialog(s.hwnd,false,error);
    s.dialog=false;
    if (error) answer(s,id,"{\"error\":\"Could not open the file dialog\"}");
    else if (path.empty()) answer(s,id,"{\"result\":{\"path\":\"\",\"canceled\":true}}");
    else answer(s,id,"{\"result\":{\"path\":"+quote(utf8(path))+",\"canceled\":false}}");
  });
}
extern "C" void infra_windows_save(const char *id,const char *data,size_t n) {
  dispatch([id=std::string(id),data=std::string(data,n)](Session &s){
    if (s.dialog) { answer(s,id,"{\"error\":\"Another file dialog is open\"}"); return; }
    s.dialog=true;
    DWORD error{};
    auto path=file_dialog(s.hwnd,true,error);
    s.dialog=false;
    if (error) answer(s,id,"{\"error\":\"Could not open the save dialog\"}");
    else if (path.empty()) answer(s,id,"{\"result\":{\"saved\":false,\"canceled\":true}}");
    else if (!write_file(path,data,id)) answer(s,id,"{\"error\":\"Could not save the firewall script\"}");
    else answer(s,id,"{\"result\":{\"saved\":true,\"canceled\":false}}");
  });
}
