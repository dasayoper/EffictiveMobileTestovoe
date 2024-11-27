package by.dasayoper.taskmanager.specification;

import by.dasayoper.taskmanager.model.Account;
import by.dasayoper.taskmanager.model.BaseEntity;
import by.dasayoper.taskmanager.model.Task;
import jakarta.persistence.criteria.Join;
import jakarta.persistence.criteria.JoinType;
import jakarta.persistence.criteria.Predicate;
import org.springframework.data.jpa.domain.Specification;

public class AccountSpecification {

    public static Specification<Account> firstNameContains(String firstName) {
        return (root, query, criteriaBuilder) ->
                criteriaBuilder.like(criteriaBuilder.lower(root.get("firstName")), "%" + firstName.toLowerCase() + "%");
    }

    public static Specification<Account> lastNameContains(String lastName) {
        return (root, query, criteriaBuilder) ->
                criteriaBuilder.like(criteriaBuilder.lower(root.get("lastName")), "%" + lastName.toLowerCase() + "%");
    }

    public static Specification<Account> emailContains(String email) {
        return (root, query, criteriaBuilder) ->
                criteriaBuilder.like(criteriaBuilder.lower(root.get("email")), "%" + email.toLowerCase() + "%");
    }

    public static Specification<Account> hasAssignedTasks(Boolean hasAssignedTasks) {
        return (root, query, criteriaBuilder) -> {
            Join<Account, Task> tasksJoin = root.join("assignedTasks", JoinType.LEFT);

            Predicate validStatus = criteriaBuilder.and(
                    criteriaBuilder.notEqual(tasksJoin.get("status"), Task.TaskStatus.NEW),
                    criteriaBuilder.notEqual(tasksJoin.get("status"), Task.TaskStatus.CLOSED)
            );

            Predicate invalidStatus = criteriaBuilder.or(
                    criteriaBuilder.equal(tasksJoin.get("status"), Task.TaskStatus.NEW),
                    criteriaBuilder.equal(tasksJoin.get("status"), Task.TaskStatus.CLOSED)
            );

            Predicate hasTasks = criteriaBuilder.isNotEmpty(root.get("assignedTasks"));

            if (hasAssignedTasks != null && hasAssignedTasks) {
                return criteriaBuilder.and(hasTasks, validStatus);
            } else {
                return criteriaBuilder.and(hasTasks, invalidStatus);
            }
        };
    }

    public static Specification<Account> notDeleted() {
        return (root, query, criteriaBuilder) ->
                criteriaBuilder.notEqual(root.get("state"), BaseEntity.State.DELETED);
    }
}
