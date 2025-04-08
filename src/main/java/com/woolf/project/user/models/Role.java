package com.woolf.project.user.models;

import com.woolf.project.user.enums.Roles;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@Entity
public class Role extends BaseModel{
    @Enumerated(EnumType.STRING)
    private Roles name;
}
