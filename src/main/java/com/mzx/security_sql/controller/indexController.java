package com.mzx.security_sql.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import java.util.Date;

@Controller
public class indexController {


    @ResponseBody
    @RequestMapping("/db/a")
    public String dba(){
        return "dba";
    }

    @ResponseBody
    @RequestMapping("/admin/a")
    public String admina(){
        return "admina";
    }


    @ResponseBody
    @RequestMapping("/user/a")
    public String usera(){
        return "usera";
    }


    @RequestMapping("/login_page")
    public String loginPage(){
        return "login_page";
    }
}
