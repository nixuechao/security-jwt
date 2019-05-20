package com.zolvces.securityjwt.security.simple;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

/**
 * @author niXueChao
 * @date 2019/4/2 14:35.
 */
public class JwtLoginToken extends AbstractAuthenticationToken {

    /**登录用户信息*/
    private final Object principal;
    /**密码*/
    private Object credentials;

    /**创建一个未认证的授权令牌,
     * 这时传入的principal是用户名
     *
     */
    public JwtLoginToken(Object principal, Object credentials) {
        super(null);
        this.principal = principal;
        this.credentials = credentials;
        setAuthenticated(false);
    }

    /**创建一个已认证的授权令牌,如注释中说的那样,这个方法应该由AuthenticationProvider来调用
     * 也就是我们写的JwtAuthenticationProvider,有它完成认证后再调用这个方法,
     * 这时传入的principal为从userService中查出的UserDetails
     * @param principal
     * @param credentials
     * @param authorities
     */
    public JwtLoginToken(Object principal, Object credentials,
                                               Collection<? extends GrantedAuthority> authorities) {
        super(authorities);
        this.principal = principal;
        this.credentials = credentials;
        super.setAuthenticated(true);
    }

    @Override
    public Object getCredentials() {
        return this.credentials;
    }

    @Override
    public Object getPrincipal() {
        return this.principal;
    }
}
