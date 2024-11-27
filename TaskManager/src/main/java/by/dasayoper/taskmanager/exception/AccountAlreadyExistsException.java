package by.dasayoper.taskmanager.exception;

import lombok.Getter;
import org.springframework.http.HttpStatus;

@Getter
public class AccountAlreadyExistsException extends RuntimeException {
    private final HttpStatus httpStatus;

    public AccountAlreadyExistsException(String message) {
        super(message);
        this.httpStatus = HttpStatus.CONFLICT;
    }
}
