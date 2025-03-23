package com.woolf.project.user.dtos;

import com.woolf.project.user.models.User;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class UserDTO {
    private String name;
    private String email;
    private String address;

    public static UserDTO fromUser(User user){
        UserDTO userDto = new UserDTO();
        userDto.setName(user.getUsername());
        userDto.setEmail(user.getEmail());

        if(user.getAddress() != null){
            String addrs = user.getAddress().getStreet() +"," +
                    user.getAddress().getCity() + "," +
                    user.getAddress().getState() + "," +
                    user.getAddress().getCountry() + " - " +
                    user.getAddress().getZipcode();
            userDto.setAddress(addrs);
        }
        return userDto;
    }
}
