package by.dasayoper.taskmanager.exception;

import lombok.Getter;
import org.springframework.http.HttpStatus;

@Getter
public class CommentNotFoundException extends RuntimeException {
    private final HttpStatus httpStatus;

    public CommentNotFoundException(String message) {
        super(message);
        this.httpStatus = HttpStatus.NOT_FOUND;
    }
}
