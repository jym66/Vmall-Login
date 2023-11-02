package login

import (
	"encoding/json"
	"fmt"
	goqrcode "github.com/skip2/go-qrcode"
	"log"
	"math/rand"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type HttpClient struct {
	httpClient *http.Client
	headers    http.Header
}

type qrcode struct {
	QrToken string `json:"qrToken"`
	Content string `json:"content"`
}

type QrcodeApiResponse struct {
	ErrorDesc   string `json:"errorDesc"`
	Code        string `json:"code"`
	AccountType int    `json:"accountType"`
	UserAccount string `json:"userAccount"`
	ResultCode  string `json:"resultCode"`
	SiteID      string `json:"siteID"`
	UserID      string `json:"userID"`
}

type CasInfo struct {
	CasLoginRedirectUrl string `json:"casLoginRedirectUrl"`
}

type LoginInteractInfo struct {
	Cas CasInfo `json:"cas"`
}
type LoginInfo struct {
	IsSuccess         string `json:"isSuccess"`
	Code              string `json:"code"`
	ConfirmReturnType string `json:"confirmReturnType"`
}
type SignatureInfo struct {
	Display              string `json:"display"`
	Lang                 string `json:"lang"`
	Nonce                string `json:"nonce"`
	Prompt               string `json:"prompt"`
	Scope                string `json:"scope"`
	ClientId             string `json:"client_id"`
	CodeChallengeMethod  string `json:"code_challenge_method"`
	FlowID               string `json:"flowID"`
	H                    string `json:"h"`
	IncludeGrantedScopes string `json:"include_granted_scopes"`
	RedirectUri          string `json:"redirect_uri"`
	ResponseType         string `json:"response_type"`
	AccessType           string `json:"access_type"`
	V                    string `json:"v"`
}

type LoginWay struct {
	LoginInteractInfo LoginInteractInfo `json:"loginInteractInfo"`
	SignatureInfo     SignatureInfo     `json:"signatureInfo"`
}

type PageInfo struct {
	Footer struct {
		UserPrivacyPolicyUrl      string `json:"userPrivacyPolicyUrl"`
		CookieUrl                 string `json:"cookieUrl"`
		CopyRightTo               string `json:"copyRightTo"`
		EULAUrl                   string `json:"eULAUrl"`
		CookieBannerExpires       string `json:"cookieBannerExpires"`
		ShowCookie                bool   `json:"showCookie"`
		CopyRightFrom             string `json:"copyRightFrom"`
		FaqHtml                   string `json:"faqHtml"`
		HwAccountAndPrivacyNotice string `json:"hwAccountAndPrivacyNotice"`
	} `json:"footer"`
	PageName     string `json:"pageName"`
	PageTokenKey string `json:"pageTokenKey"`
	Header       struct {
		AdHeadTitle string `json:"adHeadTitle"`
		Favicon     string `json:"favicon"`
		PicSrc      string `json:"picSrc"`
	} `json:"header"`
	LogID     string `json:"logID"`
	PageToken string `json:"pageToken"`
	LocalInfo struct {
		IsUseSMSLoginRegister            bool     `json:"isUseSMSLoginRegister"`
		GrayScaleWeb                     bool     `json:"grayScaleWeb"`
		ClientID                         string   `json:"clientID"`
		QrcodeRequestInterval            int      `json:"qrcodeRequestInterval"`
		FromApp                          bool     `json:"fromApp"`
		PetalMailSuffixes                []string `json:"petalMailSuffixes"`
		SessionStorageType               string   `json:"sessionStorageType"`
		ReqClientType                    string   `json:"reqClientType"`
		PriorityLoginType                string   `json:"priorityLoginType"`
		GrayScaleWap                     bool     `json:"grayScaleWap"`
		IsOpenApealSelf                  bool     `json:"isOpenApealSelf"`
		IsUseSessionLocalStage           bool     `json:"isUseSessionLocalStage"`
		PostRemoteLogin                  string   `json:"postRemoteLogin"`
		CookieUrl                        string   `json:"cookieUrl"`
		ThirdLoginList                   string   `json:"thirdLoginList"`
		CarrierName                      string   `json:"carrierName"`
		SecCodeAndSecondLoginFaqUrl      string   `json:"secCodeAndSecondLoginFaqUrl"`
		IsMobile                         bool     `json:"isMobile"`
		State                            string   `json:"state"`
		GeetestLoadingTimeOut            string   `json:"geetestLoadingTimeOut"`
		IsOpenSMSLogin                   bool     `json:"isOpenSMSLogin"`
		AsyncURL                         string   `json:"asyncURL"`
		IsUsedDeviceFingerSite           bool     `json:"isUsedDeviceFingerSite"`
		ResourseJsImgCssWebUrl           string   `json:"resourse_js_img_css_webUrl"`
		ManagedIDAccountAndPrivacyNotice string   `json:"managedIDAccountAndPrivacyNotice"`
		DefaultCallingCode               string   `json:"defaultCallingCode"`
		DisplayCaptchaType               string   `json:"displayCaptchaType"`
		LocalHttps                       string   `json:"localHttps"`
		LowLogin                         string   `json:"lowLogin"`
		RetryRssPath                     string   `json:"retryRssPath"`
		CarrierNameAccount               string   `json:"carrierNameAccount"`
		LocalHttpsAjaxPath               string   `json:"localHttpsAjaxPath"`
		UrlCountrySiteID                 int      `json:"urlCountrySiteID"`
		OpenCscPreprocessVerifySenceId   bool     `json:"openCscPreprocessVerifySenceId"`
		IsOpenCasPageStat                string   `json:"isOpenCasPageStat"`
		UseWapBtn                        bool     `json:"useWapBtn"`
		WapRegisterUrl                   string   `json:"wapRegisterUrl"`
		IsInLiteSDKDevClientIDBlacklist  bool     `json:"isInLiteSDKDevClientIDBlacklist"`
		OpenKPIStat                      bool     `json:"openKPIStat"`
		CscSceneId                       string   `json:"cscSceneId"`
		JsSDKReportDomain                string   `json:"jsSDKReportDomain"`
		WeChatInstalled                  bool     `json:"weChatInstalled"`
		ShowManagedIDAgr                 bool     `json:"showManagedIDAgr"`
		CsCaptchaOpen                    bool     `json:"csCaptchaOpen"`
		ManagedIDServiceAgrUrl           string   `json:"managedIDServiceAgrUrl"`
		QuickAuth                        string   `json:"quickAuth"`
		WapFindPwdUrl                    string   `json:"wapFindPwdUrl"`
		FindPwdUrl                       string   `json:"findPwdUrl"`
		IsOpenDimensionalCode            string   `json:"isOpenDimensionalCode"`
		RegionCode                       string   `json:"regionCode"`
		ShowRegLinkInLoginPagesFlag      bool     `json:"showRegLinkInLoginPagesFlag"`
		WebRegisterUrl                   string   `json:"webRegisterUrl"`
		LoginUrl                         string   `json:"loginUrl"`
		ClientNonce                      string   `json:"clientNonce"`
		Scope                            string   `json:"scope"`
		HwidApp                          bool     `json:"hwidApp"`
		Lang                             string   `json:"lang"`
		LocalHttpsAMW                    string   `json:"localHttps_AMW"`
		IsQrlogin                        bool     `json:"isQrlogin"`
		GetqrContent                     string   `json:"getqrContent"`
		LoginChannel                     string   `json:"loginChannel"`
		CsCaptchaUrl                     []string `json:"csCaptchaUrl"`
		CurrentSiteID                    int      `json:"currentSiteID"`
		NoPassRegUrl                     string   `json:"noPassRegUrl"`
		Special                          bool     `json:"special"`
		ThemeName                        string   `json:"themeName"`
		CarrierLogo                      string   `json:"carrierLogo"`
		Service                          string   `json:"service"`
		CookieVersion                    string   `json:"cookieVersion"`
		LogID                            string   `json:"logID"`
		FlowID                           string   `json:"flowID"`
		UrlQuery                         string   `json:"urlQuery"`
		IsOpenLocalCacheRisk             bool     `json:"isOpenLocalCacheRisk"`
	} `json:"localInfo"`
	IsSuccess int `json:"isSuccess"`
}

type codeRemoteLogin struct {
	CallbackURL string `json:"callbackURL"`
	IsSuccess   int    `json:"isSuccess"`
}

func NewHttpClient() *HttpClient {
	jar, err := cookiejar.New(nil)
	if err != nil {
		log.Fatal(err)
	}
	proxyURL, err := url.Parse("http://127.0.0.1:8888")
	if err != nil {
		log.Fatal(err)
	}
	headers := http.Header{
		"Content-Type":       []string{"application/x-www-form-urlencoded"},
		"Accept-Language":    []string{"zh-CN,zh;q=0.9,en;q=0.8"},
		"Cache-Control":      []string{"no-cache"},
		"accept":             []string{"application/json, text/plain, */*"},
		"User-Agent":         []string{"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36"},
		"Sec-Ch-Ua":          []string{"\"Chromium\";v=\"118\", \"Google Chrome\";v=\"118\", \";Not A Brand\";v=\"99\""},
		"Sec-Ch-Ua-Mobile":   []string{"?0"},
		"Sec-Ch-Ua-Platform": []string{"\"macOS\""},
		"Sec-Fetch-Dest":     []string{"empty"},
		"sec-fetch-mode":     []string{"cors"},
		"Sec-Fetch-Site":     []string{"same-origin"},
	}
	return &HttpClient{
		httpClient: &http.Client{
			Timeout: time.Second * 10,
			Jar:     jar,
			Transport: &http.Transport{
				Proxy: http.ProxyURL(proxyURL),
			},
		},
		headers: headers,
	}
}
func (hc *HttpClient) getLoginWay(lw *LoginWay) {
	u := fmt.Sprintf("https://oauth-login.cloud.huawei.com/oauth2/ajax/getLoginWay?reflushCode=%.17f", rand.Float64())
	method := "POST"
	payload := strings.NewReader("response_type=code&access_type=offline&login_channel=26000000&client_id=10049053&req_client_type=26&redirect_uri=https%3A%2F%2Fwww.vmall.com%2Faccount%2Fatlogin%3Furl%3Dhttps%253A%252F%252Fwww.vmall.com%252Findex.html&scope=openid%20https%3A%2F%2Fwww.huawei.com%2Fauth%2Faccount%2Fbase.profile%20https%3A%2F%2Fwww.huawei.com%2Fauth%2Faccount%2Faccountlist%20https%3A%2F%2Fwww.huawei.com%2Fauth%2Faccount%2Fnopwdlowlogin")
	req, err := http.NewRequest(method, u, payload)
	checkError(err)
	hc.applyHeaders(req)
	req.Header.Add("Interfaceversion", "v3")
	resp, err := hc.httpClient.Do(req)
	checkError(err)
	defer resp.Body.Close()
	err = json.NewDecoder(resp.Body).Decode(&lw)
	checkError(err)
}
func (hc *HttpClient) applyHeaders(req *http.Request) {
	for key, values := range hc.headers {
		for _, value := range values {
			req.Header.Add(key, value)
		}
	}
}
func (hc *HttpClient) getPageInfo(lw *LoginWay, pg *PageInfo) {
	u := fmt.Sprintf("https://id1.cloud.huawei.com/CAS/IDM_W/ajaxHandler/login/getPageInfo?reflushCode=%.17f&cVersion=UP_CAS_6.12.0.100_live", rand.Float64())
	method := "POST"
	params1 := "reqClientType=26&loginChannel=26000000&clientID=10049053&lang=zh-cn&languageCode=zh-cn&state=null&regionCode=cn&loginUrl=https://id1.cloud.huawei.com:443/CAS/portal/loginAuth.html&themeName=huawei&scope=https://www.huawei.com/auth/account/nopwdlowlogin&"
	service := fmt.Sprintf("https://oauth-login1.cloud.huawei.com/oauth2/v3/loginCallback?access_type=%s&client_id=%s&code_challenge_method=%s&display=%s&flowID=%s&include_granted_scopes=%s&lang=%s&nonce=%s&prompt=%s&redirect_uri=%s&response_type=code&scope=%s&v=%s", lw.SignatureInfo.AccessType, lw.SignatureInfo.ClientId, lw.SignatureInfo.CodeChallengeMethod, lw.SignatureInfo.Display, lw.SignatureInfo.FlowID, lw.SignatureInfo.IncludeGrantedScopes, lw.SignatureInfo.Lang, lw.SignatureInfo.Nonce, lw.SignatureInfo.Prompt, lw.SignatureInfo.RedirectUri, lw.SignatureInfo.Scope, lw.SignatureInfo.V)
	params := fmt.Sprintf("%s&service=%s&validated=true&pageName=login", params1, url.QueryEscape(service))
	payload := strings.NewReader(params)
	req, err := http.NewRequest(method, u, payload)
	checkError(err)
	hc.applyHeaders(req)
	resp, err := hc.httpClient.Do(req)
	checkError(err)
	defer resp.Body.Close()
	err = json.NewDecoder(resp.Body).Decode(&pg)
	checkError(err)
}
func (hc *HttpClient) login(params string) {
	var login LoginInfo
	//通过codeRemoteLogin获得的url参数，向这个url提交，再得到一个url，即可登陆成功
	u := fmt.Sprintf("https://oauth-login1.cloud.huawei.com/oauth2/ajax/login?reflushCode=%.17f&display=page", rand.Float64())
	method := "POST"
	payload := strings.NewReader(strings.Split(params, "?")[1])
	req, err := http.NewRequest(method, u, payload)
	checkError(err)
	hc.applyHeaders(req)
	req.Header.Add("Interfaceversion", "v3")
	resp, err := hc.httpClient.Do(req)
	checkError(err)
	defer resp.Body.Close()
	err = json.NewDecoder(resp.Body).Decode(&login)
	checkError(err)
	req, err = http.NewRequest("GET", login.Code, nil)
	checkError(err)
	resp, err = hc.httpClient.Do(req)
	checkError(err)
	defer resp.Body.Close()
	if hc.getCookies("https://vmall.com", "euid") != "" {
		log.Println("登陆成功")
	} else {
		log.Println("登陆失败")
	}
}
func (hc *HttpClient) codeRemoteLogin(lw *LoginWay, pg *PageInfo, api *QrcodeApiResponse) {
	var codeRemote codeRemoteLogin
	u := fmt.Sprintf("https://id1.cloud.huawei.com/CAS/IDM_W/ajaxHandler/codeRemoteLogin?reflushCode=%.18f&cVersion=UP_CAS_6.12.0.100_live", rand.Float64())
	method := "POST"
	qRCode := hc.getCookies("https://id1.cloud.huawei.com/DimensionalCode/", "qRCode")
	service := fmt.Sprintf("https://oauth-login1.cloud.huawei.com/oauth2/v3/loginCallback?access_type=%s&client_id=%s&code_challenge_method=%s&display=%s&flowID=%s&h=%s&include_granted_scopes=%s&lang=%s&nonce=%s&prompt=%s&redirect_uri=%s&response_type=code&scope=%s&v=%s", lw.SignatureInfo.AccessType, lw.SignatureInfo.ClientId, lw.SignatureInfo.CodeChallengeMethod, lw.SignatureInfo.Display, lw.SignatureInfo.FlowID, lw.SignatureInfo.H, lw.SignatureInfo.IncludeGrantedScopes, lw.SignatureInfo.Lang, lw.SignatureInfo.Nonce, lw.SignatureInfo.Prompt, url.QueryEscape(lw.SignatureInfo.RedirectUri), url.QueryEscape(lw.SignatureInfo.Scope), lw.SignatureInfo.V)
	params1 := fmt.Sprintf("pageToken=%s&pageTokenKey=%s&reqClientType=%s&loginChannel=%s&clientID=%s&lang=%s&languageCode=zh-cn&state=null&loginUrl=https://id1.cloud.huawei.com:443/CAS/portal/loginAuth.html&service=%s&appID=com.huawei.hwidweb&userID=%s&siteID=%s&accountType=%s&code=%s&qrCode=%s&userAccount=%s", pg.PageToken, pg.PageTokenKey, pg.LocalInfo.ReqClientType, pg.LocalInfo.LoginChannel, lw.SignatureInfo.ClientId, lw.SignatureInfo.Lang, url.QueryEscape(service), api.UserID, api.SiteID, strconv.Itoa(api.AccountType), api.Code, qRCode, api.UserAccount)
	payload := strings.NewReader(params1)
	req, err := http.NewRequest(method, u, payload)
	checkError(err)
	hc.applyHeaders(req)
	req.Header.Add("origin", "https://id1.cloud.huawei.com")
	resp, err := hc.httpClient.Do(req)
	checkError(err)
	defer resp.Body.Close()
	err = json.NewDecoder(resp.Body).Decode(&codeRemote)
	checkError(err)
	hc.login(codeRemote.CallbackURL)

}
func (hc *HttpClient) LoginByQrcode() {
	var qrcode qrcode
	var lw LoginWay
	var api QrcodeApiResponse
	var pg PageInfo
	log.Println("正在获取登陆参数")
	hc.getLoginWay(&lw)
	hc.getPageInfo(&lw, &pg)
	log.Println("获取登陆参数成功")
	u := "https://id1.cloud.huawei.com/DimensionalCode/getqrInfo"
	method := "POST"
	data := strings.NewReader("appID=com.huawei.hwidweb&confirmFlag=1&version=40200&reqClientType=700&loginChannel=7000700&appBrand=HUAWEI")
	req, err := http.NewRequest(method, u, data)
	checkError(err)
	hc.applyHeaders(req)
	log.Println("正在获取二维码")
	resp, err := hc.httpClient.Do(req)
	checkError(err)
	defer resp.Body.Close()
	err = json.NewDecoder(resp.Body).Decode(&qrcode)
	checkError(err)
	log.Println("获取二维码成功")
	err = goqrcode.WriteFile(qrcode.Content, goqrcode.Medium, 256, "qrcode.png")
	checkError(err)
	log.Println("生成二维码成功")
	for {
		if hc.checkQrCodeStatus(&qrcode, &api) {
			hc.codeRemoteLogin(&lw, &pg, &api)
			break
		}
		//time.Sleep(time.Second * 2)
	}
}
func (hc *HttpClient) checkQrCodeStatus(qrcode *qrcode, api *QrcodeApiResponse) bool {
	u := fmt.Sprintf("https://id1.cloud.huawei.com/DimensionalCode/async?version=40200&t=%.17f", rand.Float64())
	method := "POST"
	params := strings.NewReader("qrToken=" + qrcode.QrToken)
	req, err := http.NewRequest(method, u, params)
	checkError(err)
	hc.applyHeaders(req)
	resp, err := hc.httpClient.Do(req)
	defer resp.Body.Close()
	checkError(err)
	err = json.NewDecoder(resp.Body).Decode(&api)
	checkError(err)
	switch api.ResultCode {
	case "103000200":
		log.Println("二维码状态 等待扫码")
		return false
	case "103000202":
		log.Println("二维码状态 扫码成功")
		return false
	case "103000201":
		log.Println("二维码状态 二维码过期，请重新获取")
		return false
	case "0":
		return true
	}
	return false
}
func (hc *HttpClient) getCookies(urlStr string, key string) string {
	u, err := url.Parse(urlStr)
	checkError(err)
	cookies := hc.httpClient.Jar.Cookies(u)
	for _, cookie := range cookies {
		if cookie.Name == key {
			return cookie.Value
		}
	}
	return ""
}
func checkError(err error) {
	if err != nil {
		log.Fatal(err)
	}
}
