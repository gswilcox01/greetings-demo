package com.example.demo.domain;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class Greeting {
    private int id;
    @NotBlank
    @Size(max = 50)
    @Pattern(regexp = "^[A-Za-z0-9]*$")
    private String text;
    @NotBlank
    @Size(max = 50)
    @Pattern(regexp = "^[A-Za-z0-9]*$")
    private String language;
}
