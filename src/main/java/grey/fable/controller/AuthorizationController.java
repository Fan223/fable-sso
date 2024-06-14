package grey.fable.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsent;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.security.Principal;
import java.util.*;

/**
 * 授权控制器
 *
 * @author Fable
 * @since 2024/6/14 15:22
 */
@Controller
public class AuthorizationController {

    private final RegisteredClientRepository clientRepository;
    private final OAuth2AuthorizationConsentService consentService;

    @Autowired
    public AuthorizationController(RegisteredClientRepository clientRepository, OAuth2AuthorizationConsentService consentService) {
        this.clientRepository = clientRepository;
        this.consentService = consentService;
    }

    @GetMapping("/login")
    public String login() {
        return "login";
    }

    @GetMapping(value = "/oauth2/consent")
    public String consent(Principal principal, Model model,
                          @RequestParam(OAuth2ParameterNames.CLIENT_ID) String clientId,
                          @RequestParam(OAuth2ParameterNames.SCOPE) String scope,
                          @RequestParam(OAuth2ParameterNames.STATE) String state,
                          @RequestParam(name = OAuth2ParameterNames.USER_CODE, required = false) String userCode) {

        // 通过 clientId 获取已注册的客户端信息
        RegisteredClient registeredClient = clientRepository.findByClientId(clientId);
        if (null == registeredClient) {
            throw new NullPointerException("客户端不存在");
        }

        // 通过获取到的客户端 ID 和用户名获取已授权许可信息
        OAuth2AuthorizationConsent authorizationConsent = consentService.findById(registeredClient.getId(), principal.getName());
        Set<String> authorizedScopes = null == authorizationConsent ? Collections.emptySet() : authorizationConsent.getScopes();

        // 区分请求范围是已授权还是未授权
        Set<String> scopesToApprove = new HashSet<>();
        Set<String> approvedScopes = new HashSet<>();
        for (String requestScope : StringUtils.delimitedListToStringArray(scope, " ")) {
            if (OidcScopes.OPENID.equals(requestScope)) {
                continue;
            }
            if (authorizedScopes.contains(requestScope)) {
                approvedScopes.add(requestScope);
            } else {
                scopesToApprove.add(requestScope);
            }
        }

        model.addAttribute("clientId", clientId);
        model.addAttribute("state", state);
        model.addAttribute("scopes", withDescription(scopesToApprove));
        model.addAttribute("approvedScopes", withDescription(approvedScopes));
        model.addAttribute("principalName", principal.getName());
        model.addAttribute("userCode", userCode);
        if (StringUtils.hasText(userCode)) {
            model.addAttribute("requestURI", "/oauth2/device_verification");
        } else {
            model.addAttribute("requestURI", "/oauth2/authorize");
        }

        return "consent";
    }

    private static Set<ScopeDescription> withDescription(Set<String> scopes) {
        Set<ScopeDescription> scopeDescriptions = new HashSet<>();
        for (String scope : scopes) {
            scopeDescriptions.add(new ScopeDescription(scope));
        }
        return scopeDescriptions;
    }

    private static class ScopeDescription {

        public final String scope;
        public final String description;

        public ScopeDescription(String scope) {
            this.scope = scope;
            this.description = scopeDescriptions.getOrDefault(scope, DEFAULT_DESCRIPTION);
        }

        private static final String DEFAULT_DESCRIPTION = "未知范围-我们无法提供有关此权限的信息，请在授予此权限时谨慎使用";
        private static final Map<String, String> scopeDescriptions = new HashMap<>();

        static {
            scopeDescriptions.put(OidcScopes.PROFILE, "此应用程序将能够读取您的个人资料信息.");
            scopeDescriptions.put("message.read", "此应用程序将能够读取您的信息");
            scopeDescriptions.put("message.write", "此应用程序将能够添加新消息，它还可以编辑和删除现有消息");
            scopeDescriptions.put("other.scope", "这是范围描述的另一个范围示例");
        }
    }

    @GetMapping("/activate")
    public String activate(@RequestParam(value = "user_code", required = false) String userCode) {
        if (null != userCode) {
            return "redirect:/oauth2/device_verification?user_code=" + userCode;
        }
        return "device-activate";
    }

    @GetMapping(value = "/", params = "success")
    public String success() {
        return "device-activated";
    }

    @GetMapping("/activated")
    public String activated() {
        return "device-activated";
    }
}