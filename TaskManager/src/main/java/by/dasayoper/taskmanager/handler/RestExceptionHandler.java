package by.dasayoper.taskmanager.handler;

import by.dasayoper.taskmanager.exception.*;
import by.dasayoper.taskmanager.exception.dto.ExceptionDto;
import by.dasayoper.taskmanager.validation.http.ValidationErrorDto;
import by.dasayoper.taskmanager.validation.http.ValidationExceptionResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

import java.util.ArrayList;
import java.util.List;

@ControllerAdvice
public class RestExceptionHandler {

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ValidationExceptionResponse> handleValidationException(MethodArgumentNotValidException exception) {
        List<ValidationErrorDto> errors = new ArrayList<>();
        exception.getAllErrors().forEach(error -> {
            ValidationErrorDto errorDto = ValidationErrorDto.builder()
                    .message(error.getDefaultMessage())
                    .build();

            if (error instanceof FieldError) {
                errorDto.setField(((FieldError) error).getField());
            } else {
                errorDto.setObject(error.getObjectName());
            }
            errors.add(errorDto);
        });

        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body(ValidationExceptionResponse.builder()
                        .errors(errors)
                        .build());
    }

    @ExceptionHandler(AccountAlreadyExistsException.class)
    public ResponseEntity<ExceptionDto> handleAccountAlreadyExistsException(AccountAlreadyExistsException exception) {
        return ResponseEntity.status(exception.getHttpStatus())
                .body(ExceptionDto.builder()
                        .code(exception.getHttpStatus().value())
                        .status(exception.getHttpStatus())
                        .message(exception.getMessage())
                        .build());
    }

    @ExceptionHandler(CommentNotFoundException.class)
    public ResponseEntity<ExceptionDto> handleCommentNotFoundException(CommentNotFoundException exception) {
        return ResponseEntity.status(exception.getHttpStatus())
                .body(ExceptionDto.builder()
                        .code(exception.getHttpStatus().value())
                        .status(exception.getHttpStatus())
                        .message(exception.getMessage())
                        .build());
    }

    @ExceptionHandler(NotEnoughRightsException.class)
    public ResponseEntity<ExceptionDto> handleNotEnoughRightsException(NotEnoughRightsException exception) {
        return ResponseEntity.status(exception.getHttpStatus())
                .body(ExceptionDto.builder()
                        .code(exception.getHttpStatus().value())
                        .status(exception.getHttpStatus())
                        .message(exception.getMessage())
                        .build());
    }

    @ExceptionHandler(TaskNotFoundException.class)
    public ResponseEntity<ExceptionDto> handleTaskNotFoundException(TaskNotFoundException exception) {
        return ResponseEntity.status(exception.getHttpStatus())
                .body(ExceptionDto.builder()
                        .code(exception.getHttpStatus().value())
                        .status(exception.getHttpStatus())
                        .message(exception.getMessage())
                        .build());
    }

    @ExceptionHandler(UserAccountNotFoundException.class)
    public ResponseEntity<ExceptionDto> handleProductNotFoundException(UserAccountNotFoundException exception) {
        return ResponseEntity.status(exception.getHttpStatus())
                .body(ExceptionDto.builder()
                        .code(exception.getHttpStatus().value())
                        .status(exception.getHttpStatus())
                        .message(exception.getMessage())
                        .build());
    }


}
