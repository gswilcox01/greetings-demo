package com.example.demo.controller;

import com.example.demo.domain.Greeting;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/v*/hello")
public class HelloController {

    @GetMapping("/{name}")
    public String hello(@RequestParam Map<String, String> params,
                             @RequestHeader Map<String, String> headers,
                             HttpServletResponse response,
                             @PathVariable String name) {

        for (String key : params.keySet()) {
            response.addCookie(new Cookie(key, params.get(key)));
        }

        for (String key : headers.keySet()) {
            if (key.toUpperCase().startsWith("XXX")) {
                response.addHeader(key, headers.get(key));
            }
        }

        return "Hello " + name;
    }

//    @PostMapping(consumes="text/plain")
    @RequestMapping(method = RequestMethod.POST, consumes="text/plain")
    public String helloBody(@RequestBody String name) {
        return "Hello " + name;
    }
}
