package com.upgrad.proman.api.controller;

import com.upgrad.proman.api.model.CreateUserRequest;
import com.upgrad.proman.api.model.CreateUserResponse;
import com.upgrad.proman.api.model.UserDetailsResponse;
import com.upgrad.proman.api.model.UserStatusType;
import com.upgrad.proman.service.business.UserAdminBusinessService;
import com.upgrad.proman.service.entity.UserEntity;
import com.upgrad.proman.service.exception.ResourceNotFoundException;
import com.upgrad.proman.service.exception.UnauthorizedException;
import com.upgrad.proman.service.type.UserStatus;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.time.ZonedDateTime;
import java.util.UUID;

@RestController
@RequestMapping("/")
public class UserAdminController {

    @Autowired
    private UserAdminBusinessService userAdminBusinessService;

    @GetMapping(value = "/users/{id}", produces = MediaType.APPLICATION_JSON_UTF8_VALUE)
    public ResponseEntity<UserDetailsResponse> getUser(@PathVariable("id") final String  userUuid,
                                                       @RequestHeader("authorization") final String authorization) throws ResourceNotFoundException, UnauthorizedException {
        String[] bearerToken = authorization.split("Bearer ");
        final  UserEntity userEntity = userAdminBusinessService.getUser(userUuid, bearerToken[1]);

        UserDetailsResponse userDetailsResponse = new UserDetailsResponse()
                .id(userEntity.getUuid())
                .firstName(userEntity.getFirstName())
                .lastName(userEntity.getLastName())
                .emailAddress(userEntity.getEmail())
                .mobileNumber(userEntity.getMobilePhone())
                .status(UserStatusType.valueOf(UserStatus.getEnum(userEntity.getStatus()).name()));
        return new ResponseEntity<UserDetailsResponse>(userDetailsResponse, HttpStatus.OK);

    }

    @PostMapping(path = "/users", consumes = MediaType.APPLICATION_JSON_UTF8_VALUE, produces = MediaType.APPLICATION_JSON_UTF8_VALUE)
    public ResponseEntity<CreateUserResponse> createUser( final CreateUserRequest createUserRequest){

        UserEntity userEntity = new UserEntity();
        userEntity.setFirstName(createUserRequest.getFirstName());
        userEntity.setLastName(createUserRequest.getLastName());
        userEntity.setEmail(createUserRequest.getEmailAddress());
        userEntity.setMobilePhone(createUserRequest.getMobileNumber());
        userEntity.setCreatedAt(ZonedDateTime.now());
        userEntity.setCreatedBy("api-backend");
        userEntity.setUuid(UUID.randomUUID().toString());
        userEntity.setStatus(UserStatus.ACTIVE.getCode());

        userAdminBusinessService.createUser(userEntity);

        CreateUserResponse userResponse = new CreateUserResponse().id(userEntity.getUuid()).status(UserStatusType.ACTIVE);

        return new ResponseEntity<CreateUserResponse>(userResponse, HttpStatus.CREATED);

    }

    @GetMapping("/")
    public  String index(){
        return "App is live!";
    }
}
