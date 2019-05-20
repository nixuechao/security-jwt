package com.zolvces.securityjwt.security.simple;

import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;

import javax.servlet.http.HttpServletRequest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/** 配置路径访问限制,若你的用户角色比较简单,不需要存数据库,
 * 可以在ApplicationConfigurerAdapter里配置如
 *    httpSecurity
 *    .authorizeRequests()
 *    .antMatchers("/order").....
 *
 * @author niXueChao
 * @date 2019/4/10 10:33.
 */
@Component("accessDecisionService")
public class AccessDecisionService {

    private AntPathMatcher antPathMatcher = new AntPathMatcher();

    public boolean hasPermission(HttpServletRequest request, Authentication auth) {

        //不需要登录也能访问的(permitAll)
        for (String url : Arrays.asList("/publicMsg")) {
            if (antPathMatcher.match(url, request.getRequestURI())) {
                return true;
            }
        }

        if (auth instanceof AnonymousAuthenticationToken) {
            return false;
        }

        UserDetails user = (UserDetails) auth.getPrincipal();
        String userName = user.getUsername();
        //根据用户名查出能访问哪些url, urls=findUrlByUserName()
        List<String> urls = queryUrlByUserName(userName);
        for (String url : urls) {
            if (antPathMatcher.match(url, request.getRequestURI())) {
                return true;
            }
        }
        return false;
    }

    /**
     * 模拟数据库查询用户权限
     *
     * @param userName
     * @return
     */
    private List<String> queryUrlByUserName(String userName) {
        switch (userName) {
            case "admin":
                return Arrays.asList("/innerMsg", "/secret");
            case "user":
                return Arrays.asList("/innerMsg");
            default:
                return new ArrayList<>();
        }
    }
}
