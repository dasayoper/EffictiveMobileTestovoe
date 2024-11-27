package by.dasayoper.taskmanager.exception;

import lombok.Getter;
import org.springframework.http.HttpStatus;

@Getter
public class TaskNotFoundException extends RuntimeException {
    private final HttpStatus httpStatus;

    public TaskNotFoundException(String message) {
        super(message);
        this.httpStatus = HttpStatus.NOT_FOUND;
    }
}
