package com.woolf.project.user.models;

import jakarta.persistence.*;
import jakarta.persistence.Entity;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.OneToOne;

import java.util.List;

import lombok.Getter;
import lombok.Setter;


@Getter
@Setter
@Entity
public class User extends BaseModel {
    private String name;
    private String hashedPassword;
    private String email;

    @OneToOne(cascade = CascadeType.ALL)
    @JoinColumn(name = "address_id",  referencedColumnName = "id")
    private Address address;

    @ManyToMany(fetch = FetchType.EAGER)
    private List<Role> roles;

    private String resetPasswordQuestion;
    private String resetPasswordAnswer;
}
