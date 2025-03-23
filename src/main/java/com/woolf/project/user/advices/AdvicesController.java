package com.woolf.project.user.advices;


import com.woolf.project.user.dtos.ExceptionDTO;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

@ControllerAdvice
public class AdvicesController {

    @ExceptionHandler(RuntimeException.class)
    ResponseEntity<ExceptionDTO> handleRuntimeException(RuntimeException ex){
        ExceptionDTO exceptionDTO = new ExceptionDTO(HttpStatus.INTERNAL_SERVER_ERROR, ex.getMessage());
        ex.printStackTrace();
        return new ResponseEntity<>(exceptionDTO, HttpStatus.INTERNAL_SERVER_ERROR);
    }
}