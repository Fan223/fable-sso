package grey.fable.config;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import grey.fable.device.DeviceClientAuthenticationConverter;
import grey.fable.device.DeviceClientAuthenticationProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.util.*;
import java.util.stream.Collectors;

/**
 * 授权服务器配置类
 *
 * @author Fable
 * @since 2024/6/13 15:17
 */
@Configuration
public class AuthorizationServerConfig {

    @Bean
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http,
                                                                      RegisteredClientRepository registeredClientRepository,
                                                                      AuthorizationServerSettings authorizationServerSettings) throws Exception {
        // 应用默认设置, 忽略端点的 csrf 校验
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);

        DeviceClientAuthenticationProvider deviceClientAuthenticationProvider =
                new DeviceClientAuthenticationProvider(registeredClientRepository);
        DeviceClientAuthenticationConverter deviceClientAuthenticationConverter =
                new DeviceClientAuthenticationConverter(authorizationServerSettings.getDeviceAuthorizationEndpoint());

        http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
                // 开启 OpenID Connect 1.0 协议相关端点
                .oidc(oidcConfigurer -> oidcConfigurer.userInfoEndpoint(
                        configurer -> configurer.userInfoMapper(context -> {
                            OAuth2AccessToken accessToken = context.getAccessToken();
                            String username = context.getAuthorization().getPrincipalName();

                            Map<String, Object> claims = Map.of("access_token", accessToken, "username", username);
                            return new OidcUserInfo(claims);
                        })))
                // 自定义用户确认授权页
                .authorizationEndpoint(configurer -> configurer.consentPage("/oauth2/consent"))
                // 自定义设备码用户验证页
                .deviceAuthorizationEndpoint(configurer -> configurer.verificationUri("/activate"))
                // 自定义设备码用户确认授权页
                .deviceVerificationEndpoint(configurer -> configurer.consentPage("/oauth2/consent"))
                // 客户端认证添加设备码的 Provider 和 Converter
                .clientAuthentication(configurer -> configurer.authenticationProvider(deviceClientAuthenticationProvider)
                        .authenticationConverter(deviceClientAuthenticationConverter));

        // 未登录访问认证端点时重定向至登录页面
        http.exceptionHandling(configurer -> configurer.defaultAuthenticationEntryPointFor(
                        new LoginUrlAuthenticationEntryPoint("/login"), new MediaTypeRequestMatcher(MediaType.TEXT_HTML)))
                // 处理使用 Access Token 访问用户信息端点和客户端注册端点
                .oauth2ResourceServer(configurer -> configurer.jwt(Customizer.withDefaults()));
        return http.build();
    }

    /**
     * 配置客户端存储, 对应 oauth2_registered_client 表, 这里是加载的时候写死的, 可以改成请求方式注册客户端信息
     *
     * @param jdbcTemplate    数据源信息
     * @param passwordEncoder 密码解析器
     * @return {@link RegisteredClientRepository}
     * @author Fable
     * @since 2024/6/14 15:01
     */
    @Bean
    public RegisteredClientRepository registeredClientRepository(JdbcTemplate jdbcTemplate, PasswordEncoder passwordEncoder) {
        // 基于数据库存储客户端
        JdbcRegisteredClientRepository registeredClientRepository = new JdbcRegisteredClientRepository(jdbcTemplate);

        // Token 相关配置
        TokenSettings tokenSettings = TokenSettings.builder()
                // 令牌存活时间
                .accessTokenTimeToLive(Duration.ofHours(2))
                // 是否重用刷新令牌
                .reuseRefreshTokens(true)
                // 刷新令牌存活时间
                .refreshTokenTimeToLive(Duration.ofDays(7))
                .build();
        // 客户端相关配置
        ClientSettings clientSettings = ClientSettings.builder()
                // 是否需要用户授权确认
                .requireAuthorizationConsent(true)
                .build();

        // 初始化客户端
        RegisteredClient client = RegisteredClient.withId(UUID.randomUUID().toString())
                // 客户端 ID
                .clientId("messaging-client")
                // 客户端秘钥, 使用密码解析器加密
                .clientSecret(passwordEncoder.encode("123456"))
                // 客户端认证方式, 基于请求头的认证
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                // 获取授权时支持的方式
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                // 授权码模式回调地址, 授权服务器向当前客户端响应时调用下面地址, 不能使用 localhost
                .redirectUri("http://127.0.0.1:8080/login/oauth2/code/messaging-client-oidc")
                // OIDC 授权范围, 获取授权时请求 OIDC 的 scope 授权服务会返回 id_token, 同时支持默认用户信息端点 /userinfo
                .scope(OidcScopes.OPENID)
                .scope(OidcScopes.PROFILE)
                // 自定义 scope
                .scope("message.read")
                .scope("message.write")
                .tokenSettings(tokenSettings)
                .clientSettings(clientSettings)
                .build();
        RegisteredClient clientById = registeredClientRepository.findByClientId(client.getClientId());
        if (null == clientById) {
            registeredClientRepository.save(client);
        }

        // 扩展授权码客户端
        RegisteredClient pkceClient = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("pkce-client")
                // 公共客户端
                .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                // 授权码模式, 因为是扩展授权码, 所以还是授权码的流程, 改变的只是参数
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .redirectUri("http://127.0.0.1:8080/login/oauth2/code/pkce-client-oidc")
                .scope("message.read")
                .scope("message.write")
                .tokenSettings(tokenSettings)
                .clientSettings(clientSettings)
                .build();
        RegisteredClient pkceClientById = registeredClientRepository.findByClientId(pkceClient.getClientId());
        if (null == pkceClientById) {
            registeredClientRepository.save(pkceClient);
        }

        // 设备码授权客户端
        RegisteredClient deviceClient = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("device-message-client")
                .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                // 设备码授权
                .authorizationGrantType(AuthorizationGrantType.DEVICE_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .scope("message.read")
                .scope("message.write")
                .build();
        RegisteredClient deviceClientById = registeredClientRepository.findByClientId(deviceClient.getClientId());
        if (null == deviceClientById) {
            registeredClientRepository.save(deviceClient);
        }

        return registeredClientRepository;
    }

    /**
     * 配置基于数据库的 OAuth2 授权管理服务, 授权信息表, 对应 oauth2_authorization 表
     *
     * @param jdbcTemplate               数据源信息
     * @param registeredClientRepository 已注册的客户端存储
     * @return {@link JdbcOAuth2AuthorizationService}
     * @author Fable
     * @since 2024/6/14 15:03
     */
    @Bean
    public JdbcOAuth2AuthorizationService authorizationService(JdbcTemplate jdbcTemplate, RegisteredClientRepository registeredClientRepository) {
        return new JdbcOAuth2AuthorizationService(jdbcTemplate, registeredClientRepository);
    }

    /**
     * 配置基于数据库的授权确认管理服务, 把资源拥有者授权确认信息保存到数据库, 对应 oauth2_authorization_consent 表
     *
     * @param jdbcTemplate               数据源信息
     * @param registeredClientRepository 已注册的客户端存储
     * @return {@link JdbcOAuth2AuthorizationConsentService}
     * @author Fable
     * @since 2024/6/14 15:04
     */
    @Bean
    public JdbcOAuth2AuthorizationConsentService authorizationConsentService(JdbcTemplate jdbcTemplate, RegisteredClientRepository registeredClientRepository) {
        return new JdbcOAuth2AuthorizationConsentService(jdbcTemplate, registeredClientRepository);
    }

    /**
     * 配置 JWK 源, 使用非对称加密, 公开用于检索匹配指定选择器的 JWK 的方法
     *
     * @return {@link JWKSource<SecurityContext>}
     * @author Fable
     * @since 2024/6/14 15:05
     */
    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        KeyPair keyPair = generateRsaKey();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        RSAKey rsaKey = new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID(UUID.randomUUID().toString())
                .build();
        JWKSet jwkSet = new JWKSet(rsaKey);
        return (jwkSelector, securityContext) -> jwkSelector.select(jwkSet);
    }

    /**
     * 生成 RSA 密钥对，提供给 JWK
     *
     * @return {@link KeyPair}
     * @author Fable
     * @since 2024/6/14 15:05
     */
    private static KeyPair generateRsaKey() {
        KeyPair keyPair;
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            keyPair = keyPairGenerator.generateKeyPair();
        } catch (Exception ex) {
            throw new IllegalStateException(ex);
        }
        return keyPair;
    }

    /**
     * 配置 JWT 解码器
     *
     * @param jwkSource JWK 源
     * @return {@link JwtDecoder}
     * @author Fable
     * @since 2024/6/14 15:06
     */
    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    /**
     * 授权服务器配置, 设置 JWT 签发者、默认端点请求地址等
     *
     * @return {@link AuthorizationServerSettings}
     * @author Fable
     * @since 2024/6/14 15:06
     */
    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder()
                // 设置 Token 签发地址, http(s)://{ip}:{port}/context-path 或 http(s)://domain.com/context-path
                .issuer("http://172.16.63.132:9000")
                .build();
    }

    /**
     * 自定义 JWT 信息
     *
     * @return {@link OAuth2TokenCustomizer<JwtEncodingContext>}
     * @author Fable
     * @since 2024/6/17 14:39
     */
    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> jwtCustomizer() {
        return context -> {
            // 检查登录用户信息是不是 UserDetails, 排除掉没有用户参与的流程
            if (context.getPrincipal().getPrincipal() instanceof UserDetails userDetails) {
                // 获取用户的权限
                Collection<? extends GrantedAuthority> authorities = userDetails.getAuthorities();
                // 提取权限并转为字符串
                Set<String> authoritySet = Optional.ofNullable(authorities).orElse(Collections.emptySet()).stream()
                        .map(GrantedAuthority::getAuthority).collect(Collectors.toSet());

                // 获取申请的 scopes
                Set<String> authorizedScopes = context.getAuthorizedScopes();
                // 合并用户权限和 scopes
                authoritySet.addAll(authorizedScopes);

                // 将权限信息放入 Jwt 的 Claims 中
                JwtClaimsSet.Builder claims = context.getClaims();
                claims.claim("authorities", authoritySet);
            }
        };
    }
}