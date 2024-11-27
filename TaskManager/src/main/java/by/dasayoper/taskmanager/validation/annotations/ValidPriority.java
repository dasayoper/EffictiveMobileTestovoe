package by.dasayoper.taskmanager.validation.annotations;

import by.dasayoper.taskmanager.validation.validators.PriorityValidator;
import jakarta.validation.Constraint;
import jakarta.validation.Payload;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Target({ElementType.FIELD, ElementType.PARAMETER})
@Retention(RetentionPolicy.RUNTIME)
@Constraint(validatedBy = PriorityValidator.class)
public @interface ValidPriority {
    String message() default "Priority is invalid";

    Class<?>[] groups() default {};

    Class<? extends Payload>[] payload() default {};
}
