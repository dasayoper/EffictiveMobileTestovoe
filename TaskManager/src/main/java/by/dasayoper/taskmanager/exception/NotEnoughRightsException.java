package by.dasayoper.taskmanager.exception;

import lombok.Getter;
import org.springframework.http.HttpStatus;

@Getter
public class NotEnoughRightsException extends RuntimeException {
    private final HttpStatus httpStatus;

    public NotEnoughRightsException(String message) {
        super(message);
        this.httpStatus = HttpStatus.FORBIDDEN;
    }
}
