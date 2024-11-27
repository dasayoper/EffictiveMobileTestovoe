package by.dasayoper.taskmanager.specification;

import by.dasayoper.taskmanager.model.BaseEntity;
import by.dasayoper.taskmanager.model.Task;
import org.springframework.data.jpa.domain.Specification;

import java.util.UUID;

public class TaskSpecification {
    public static Specification<Task> titleContains(String titlePart) {
        return (root, query, criteriaBuilder) ->
                titlePart == null || titlePart.isBlank()
                        ? criteriaBuilder.conjunction()
                        : criteriaBuilder.like(criteriaBuilder.lower(root.get("title")), "%" + titlePart.toLowerCase() + "%");
    }

    public static Specification<Task> descriptionContains(String descriptionPart) {
        return (root, query, criteriaBuilder) ->
                descriptionPart == null || descriptionPart.isBlank()
                        ? criteriaBuilder.conjunction()
                        : criteriaBuilder.like(criteriaBuilder.lower(root.get("description")), "%" + descriptionPart.toLowerCase() + "%");
    }

    public static Specification<Task> hasStatus(Task.TaskStatus status) {
        return (root, query, criteriaBuilder) ->
                status == null
                        ? criteriaBuilder.conjunction()
                        : criteriaBuilder.equal(root.get("status"), status);
    }

    public static Specification<Task> hasPriority(Task.TaskPriority priority) {
        return (root, query, criteriaBuilder) ->
                priority == null
                        ? criteriaBuilder.conjunction()
                        : criteriaBuilder.equal(root.get("priority"), priority);
    }

    public static Specification<Task> hasAuthor(UUID authorId) {
        return (root, query, criteriaBuilder) ->
                authorId == null
                        ? criteriaBuilder.conjunction()
                        : criteriaBuilder.equal(root.get("author").get("id"), authorId);
    }

    public static Specification<Task> hasExecutor(UUID executorId) {
        return (root, query, criteriaBuilder) ->
                executorId == null
                        ? criteriaBuilder.conjunction()
                        : criteriaBuilder.equal(root.get("executor").get("id"), executorId);
    }

    public static Specification<Task> notDeleted() {
        return (root, query, criteriaBuilder) ->
               criteriaBuilder.notEqual(root.get("state"), BaseEntity.State.DELETED);
    }
}
