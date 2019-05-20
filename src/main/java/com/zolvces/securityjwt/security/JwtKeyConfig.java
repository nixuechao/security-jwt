package com.zolvces.securityjwt.security;


import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.jwt.crypto.sign.RsaSigner;
import org.springframework.security.jwt.crypto.sign.RsaVerifier;

/**
 * @author niXueChao
 * @date 2019/3/29 14:30.
 */
@Configuration
public class JwtKeyConfig {

    /**RSA私钥*/
    private static final String PRIVATE_KEY ="-----BEGIN RSA PRIVATE KEY-----" +
            "MIICWwIBAAKBgQCM1YBbzMijYIp4/mf1+gdVBXQMJEv5KpuTDh6DiTGJAk1yrsWA" +
            "RfqjpC83/t0xzpmvHa1M7WykUg5E0PmneNddyD/MTjkCDNhqBgr0AnJTZsTnEjMa" +
            "PB0cXeVF1ty1p+ZBuvHKMvhJwqgNmQd7uGpl2Rq1gR1L86YTWSkYceSoNwIDAQAB" +
            "AoGAcYrr+pcGp5l86oGJhWm4IZbM8cENs2vjk9LNTRT9580AbdZ0Cq/gm7ASFZ4X" +
            "7UD47JMLljrQ3UX+lQK6VIf7cTUGZdR1nVArOqJaMKVvCYkwqR6bm5Gc6qx6XWAW" +
            "0/PY2LcWt0cW1Q1CU65M1oM08P+ohQvE4kJI45RcoIl6VwkCQQCO0Za4bYiZWtzE" +
            "UzRka+kHa//h1YjYbQVglPLb5FuOdSm62eGQThfQRpyLU1WD6sATv9yPWxUaRCEL" +
            "Fh+s/YfrAkEA/HFDLl/Nl439/A5Q05HWhMKWZ8tt8k448mNNlefJUK1ApCuWdDWm" +
            "kBTk8ytjRvdFlVKvVVXUV8LeSyWMXpR55QJACe/rXMnCR2lbEw33B0W64RlSpJQH" +
            "AYgUZ7P1cfdhp3fff3DJkRDd90/ydH9H4/Xhh35CCnd78GftJKhVa+P4IQJABYv3" +
            "je1M9yeHjSJDZGKv8/rSkzVFFS3i0nCcI88T/VHROco7ZBJJtqC+5xjs9YI5ZS6L" +
            "67QXFlaRy9TnYKyigQJAHjuzdwDgKBj2orf6k05ri+Ks1nGvp5S4JxzcGCmkQB+l" +
            "6KOJ8lAFma4qxWKaMeNi0ekrzkSrJNEt5yJPbw1Lmg==" +
            "-----END RSA PRIVATE KEY-----";

    /**使用私钥签名*/
    @Bean
    public RsaSigner getSigner(){
        return new RsaSigner(PRIVATE_KEY);
    }

    /**使用公钥验签(这里是可以通过私钥生成密钥对,包含公钥)*/
    @Bean
    public RsaVerifier getVerifier(){
        return new RsaVerifier(PRIVATE_KEY);
    }

//    public static void main(String[] args) {
//        String jsonString = JSON.toJSONString(new HashMap<String, String>() {{
//            put("name", "zhangsan");
//            put("id", "343");
//        }});
//        System.out.println(JwtHelper.encode(jsonString, getSigner()).getEncoded());
//        Jwt decode = JwtHelper.decode("eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.aGhoaGhoaGhoaGhoaGhoaA.NXL4cJ9zMkKmaT2JnuYmr_sMRm51mil5ueje73NP5s96pOWPdHgUU875iFL-DabNu3hYOGEjO47rWnxTjzug9S_XOry7aAcKFA-cN3ROAD8rXON-dIH0gNnBYYcIWzcTAfvtGCNQjUrXyL4nxypBqog5Plw8k7V-6hS1L4PZYnM");
//        System.out.println(decode.getClaims());
//    }
}
