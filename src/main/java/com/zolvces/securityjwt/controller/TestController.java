package com.zolvces.securityjwt.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * @author niXueChao
 * @date 2019/4/2 23:34.
 */
@RestController
public class TestController {


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

}
