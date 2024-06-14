package grey.fable.device;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.util.Assert;

/**
 * 设备码授权 Provider
 *
 * @author Fable
 * @since 2024/6/14 15:50
 */
public final class DeviceClientAuthenticationProvider implements AuthenticationProvider {

    private final RegisteredClientRepository clientRepository;
    private static final String ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc6749#section-3.2.1";
    private final Log logger = LogFactory.getLog(getClass());

    public DeviceClientAuthenticationProvider(RegisteredClientRepository clientRepository) {
        Assert.notNull(clientRepository, "registeredClientRepository cannot be null");
        this.clientRepository = clientRepository;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        // 将认证信息转为 DeviceClientAuthenticationToken
        DeviceClientAuthenticationToken deviceToken = (DeviceClientAuthenticationToken) authentication;
        // 只支持公共客户端
        if (!ClientAuthenticationMethod.NONE.equals(deviceToken.getClientAuthenticationMethod())) {
            return null;
        }

        // 获取客户端 ID 并查询
        String clientId = deviceToken.getPrincipal().toString();
        RegisteredClient registeredClient = clientRepository.findByClientId(clientId);
        if (null == registeredClient) {
            throwInvalidClient(OAuth2ParameterNames.CLIENT_ID);
        }

        if (logger.isTraceEnabled()) {
            logger.trace("Retrieved registered client");
        }

        // 校验客户端
        if (!registeredClient.getClientAuthenticationMethods().contains(deviceToken.getClientAuthenticationMethod())) {
            throwInvalidClient("authentication_method");
        }

        if (logger.isTraceEnabled()) {
            logger.trace("已验证的设备客户端身份验证参数");
            logger.trace("经过身份验证的设备客户端");
        }
        return new DeviceClientAuthenticationToken(registeredClient, deviceToken.getClientAuthenticationMethod(), null);
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return DeviceClientAuthenticationToken.class.isAssignableFrom(authentication);
    }

    private static void throwInvalidClient(String parameterName) {
        OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.INVALID_CLIENT,
                "Device client authentication failed: " + parameterName, ERROR_URI
        );
        throw new OAuth2AuthenticationException(error);
    }
}