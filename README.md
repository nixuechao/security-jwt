# security-jwt
## 说明

1. 这是一个比较详尽的SpringSecurity整合JWT的例子
2. 本文并没有使用spring oauth2,不要搞混
3. 本文中的原理解释只是大概的介绍,在代码中有非常非常多的注释,配合本文食用更佳

## 自定义登录流程

* **JwtLoginFilter** 自定义的登录过滤器,把它加到SpringSecurity的过滤链中,拦截登录请求它干的事有

    1. 设置登录的url,请求的方式,其实也就是定义这个过滤器要拦截哪个请求

    2. 调用JwtAuthenticationProvider进行登录校验

    3. 校验成功调用LoginSuccessHandler,校验失败调用LoginSuccessHandler

       

* **JwtAuthenticationProvider** 自定义的认证器,账号密码对不对等校验就是它干的,主要功能
    1. 首先规定自己支持校验那种凭证(Authentication)

    2. 进行用户校验,调用JwtUserDetailServiceImpl 查询当前用户(JwtUser),判断用户账号密码是否正确,用户是否过期,被锁定等等

    3. 若用户校验失败则抛异常给JwtLoginFilter,JwtLoginFilter捕获异常调用登录失败的处理类(LoginFailureHandler)

    4. 若用户校验成功,则生成一个已认证的凭证,也就是Authentication,对应本例的JwtLoginToken 并返回给JwtLoginFilter,JwtLoginFilter拿到凭证后调用登陆成功的处理类LoginSuccessHandler

       

* **JwtLoginToken** 它就是上面说的凭证,继承自Authentication

    1. 保存当前用户的认证信息,如认证状态,用户名密码,拥有的权限等

       

* **JwtUser** 用户实体,实现UserDetails,UserDetails为springSecurity默认的用户实体抽象

  1. 主要需要实现UserDetails的几个方法,如获取用户名,密码,获取用户冻结状态等

     

* **JwtUserDetailServiceImpl** UserDetailsService的实现,提供根据用户名查询用户信息的功能
  JwtAuthenticationProvider在进行登录信息校验时就会通过它查询用户信息

  

* **LoginFailureHandler** 登录失败的处理类,被JwtLoginFilter调用,JwtLoginFilter捕获到异常,就会调用它,并且把异常信息传给它

    

* **LoginSuccessHandler** 登录成功的处理类,被JwtLoginFilter调用,并把JwtAuthenticationProvider创建的凭证(JwtLoginToken)传给它,它就可以根据凭证里的认证信息进行登录成功的处理,如生成token等

## 自定义token校验
在登录过程中,登录成功,调用LoginSuccessHandler生成了token返回给前端,那么登录成功后访问其他路径,如何根据token进行权限校验呢

* **JwtKeyConfig** 自定义的一个配置类,配置jwt,我这里的签名验证用的是RSA加密,在这里配置了密钥对

  

* **JwtHeadFilter** 实现token校验的核心,这是自定义的过滤器,主要是请求通过过滤器时,会对其携带的token进行解析和校验
  1. 获取请求中携带的token
  2. 若没有获取到token则return,调交给接下来的过滤器链处理
  3. 若有token,但是校验失败,进行校验失败处理
  4. 若token校验成功,通过从token中获取的用户信息生成一个凭证(Authentication),并放置到SecurityContext

在上面的2中没有获取到token为什么这么处理,首先springSecurity判断用户是否认证成功的标志是SecurityContext中是否有凭证(Authentication),在过滤链中,最后部分有一个匿名过滤器(AnonymousAuthenticationFilter),请求经过这个过滤器,若SecurityContext中没有凭证,会被设置一个匿名凭证.

最后决定请求是否通过的过滤器是FilterSecurityInterceptor,它会调用WebExpressionVoter来决定当前用户是否是否有权限访问url,若没有权限就会抛出AccessDeniedException,当抛出这个异常时就会有两种处理条件,若SecurityContext 中的凭证是匿名的就表示请求中没有token,需要登录,若凭证不是匿名的就表示当前用户没有权限访问次URL.

上面这个判断逻辑发生在ExceptionTranslationFilter过滤器中,抛出异常时对应的操作可以在WebSecurityConfigurerAdapter中的configure方法中配置

```java
......
http
                //身份验证入口,当需要登录却没登录时调用
                //具体为,当抛出AccessDeniedException异常时且当前是匿名用户时调用
                //匿名用户: 当过滤器链走到匿名过滤器(AnonymousAuthenticationFilter)时,
                //会进行判断SecurityContext是否有凭证(Authentication),若前面的过滤器都没有提供凭证,
                //匿名过滤器会给SecurityContext提供一个匿名的凭证(可以理解为用户名和权限为anonymous的Authentication),
                //这也是JwtHeadFilter发现请求头中没有jwtToken不作处理而直接进入下一个过滤器的原因
            .exceptionHandling().authenticationEntryPoint((request, response, authException) -> {
            response.setContentType("application/json;charset=UTF-8");
            response.getWriter().write("需要登陆");
        })

                //拒绝访问处理,当已登录,但权限不足时调用
                //抛出AccessDeniedException异常时且当不是匿名用户时调用
                .accessDeniedHandler((request, response, accessDeniedException) -> {
                    response.setContentType("application/json;charset=UTF-8");
                    response.getWriter().write("没有权限");
                })
    			......
```

## 运行demo
什么也不需要配置,直接运行就行,提供了一个testController,运行期望如下
```java
   /**任何人都能访问
     * @return
     */
    @GetMapping("/publicMsg")
    public String getMsg(){
        return "you get the message!";
    }

    /**登录的用户才能访问
     * @return
     */
    @GetMapping("/innerMsg")
    public String innerMsg(){
        return "you get the message!";
    }

    /**管理员(admin)才能访问
     * @return
     */
    @GetMapping("/secret")
    public String secret(){
        return "you get the message!";
    }
```
如果这对你有所帮助,麻烦给个star
