package by.dasayoper.taskmanager.validation.annotations;

import by.dasayoper.taskmanager.validation.validators.StatusValidator;
import jakarta.validation.Constraint;
import jakarta.validation.Payload;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Target({ElementType.FIELD, ElementType.PARAMETER})
@Retention(RetentionPolicy.RUNTIME)
@Constraint(validatedBy = StatusValidator.class)
public @interface ValidStatus {
    String message() default "Status is invalid";

    Class<?>[] groups() default {};

    Class<? extends Payload>[] payload() default {};
}
