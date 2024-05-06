package com.example.demo.controller;

import com.example.demo.domain.Greeting;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/v*/greetings")
public class GreetingsController {

    Map<Integer, Greeting> dataMap = new HashMap<>();

    public GreetingsController() {
        resetDataMap();
    }

    @Scheduled(cron = "0 0 * * * ?")
    public void resetDataMap() {
        System.out.println("clearing the map");
        dataMap.clear();
        addGreeting(1, "Hello", "English");
        addGreeting(2, "Hola", "Spanish");
        addGreeting(3, "Bonjour", "French");
        addGreeting(4, "Ciao", "Italian");
        addGreeting(5, "Hej", "Danish");
    }

    @GetMapping
    public List<Greeting> greetings() {
        return dataMap.values().stream().toList();
    }

    @GetMapping("/{id}")
    public Greeting greeting(@RequestParam Map<String, String> params,
                             @RequestHeader Map<String, String> headers,
                             HttpServletResponse response,
                             @PathVariable int id) {
        if (!dataMap.containsKey(id)) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Unable to find resource");
        }

        for (String key : params.keySet()) {
            response.addCookie(new Cookie(key, params.get(key)));
        }

        for (String key : headers.keySet()) {
            if (key.toUpperCase().startsWith("XXX")) {
                response.addHeader(key, headers.get(key));
            }
        }

        return dataMap.get(id);
    }

    @PostMapping
    public Greeting createGreeting(@Valid @RequestBody Greeting greeting) {
        if (dataMap.size() > 100) {
            throw new ResponseStatusException(HttpStatus.TOO_MANY_REQUESTS, "Greetings map is full!  Try again at the top of the hour");
        }
        greeting.setId(nextId());
        dataMap.put(greeting.getId(), greeting);
        return greeting;
    }

    @PutMapping("/{id}")
    public Greeting updateGreeting(@PathVariable int id, @Valid @RequestBody Greeting greeting) {
        if (!dataMap.containsKey(id)) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Unable to find resource");
        }
        if (id != greeting.getId()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Id in path does not match id in body");
        }
        dataMap.put(id, greeting);
        return greeting;
    }

    @DeleteMapping("/{id}")
    public void deleteGreeting(@PathVariable int id) {
        if (!dataMap.containsKey(id)) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Unable to find resource");
        }
        dataMap.remove(id);
    }

    private int nextId() {
        // get the max id in the map and add 1 to it
        return dataMap.keySet().stream().mapToInt(i -> i).max().orElse(0) + 1;
    }

    void addGreeting(int id, String text, String language) {
        dataMap.put(id, new Greeting(id, text, language));
    }
}
