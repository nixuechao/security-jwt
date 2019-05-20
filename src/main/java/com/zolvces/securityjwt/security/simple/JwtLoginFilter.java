package com.zolvces.securityjwt.security.simple;

import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * @author niXueChao
 * @date 2019/4/2 14:07.
 */
public class JwtLoginFilter extends AbstractAuthenticationProcessingFilter {


    JwtLoginFilter() {
        super(new AntPathRequestMatcher("/jwtLogin", "GET"));
    }


    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
       try {
           String userName = request.getParameter("userName");
           String password = request.getParameter("password");
           //创建未认证的凭证(etAuthenticated(false)),注意此时凭证中的主体principal为用户名
           JwtLoginToken jwtLoginToken = new JwtLoginToken(userName, password);
           //将认证详情(ip,sessionId)写到凭证
           jwtLoginToken.setDetails(new WebAuthenticationDetails(request));
           //AuthenticationManager获取受支持的AuthenticationProvider(这里也就是JwtAuthenticationProvider),
           //生成已认证的凭证,此时凭证中的主体为userDetails
           Authentication authenticatedToken = this.getAuthenticationManager().authenticate(jwtLoginToken);
           return authenticatedToken;
       }catch (Exception e){
           throw new BadCredentialsException("坏的凭证");
       }
    }

}
