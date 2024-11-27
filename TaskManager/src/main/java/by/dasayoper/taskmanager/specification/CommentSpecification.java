package by.dasayoper.taskmanager.specification;

import by.dasayoper.taskmanager.model.BaseEntity;
import by.dasayoper.taskmanager.model.Comment;
import jakarta.persistence.criteria.Predicate;
import org.springframework.data.jpa.domain.Specification;

import java.time.LocalDateTime;
import java.util.UUID;

public class CommentSpecification {
    // Фильтр по содержимому text
    public static Specification<Comment> textContains(String text) {
        return (root, query, criteriaBuilder) ->
                text == null || text.isBlank()
                        ? criteriaBuilder.conjunction()
                        : criteriaBuilder.like(criteriaBuilder.lower(root.get("text")), "%" + text.toLowerCase() + "%");
    }

    // Фильтр по authorId
    public static Specification<Comment> hasAuthor(UUID authorId) {
        return (root, query, criteriaBuilder) ->
                authorId == null
                        ? criteriaBuilder.conjunction()
                        : criteriaBuilder.equal(root.get("author").get("id"), authorId);
    }

    // Фильтр по taskId
    public static Specification<Comment> hasTask(UUID taskId) {
        return (root, query, criteriaBuilder) ->
                taskId == null
                        ? criteriaBuilder.conjunction()
                        : criteriaBuilder.equal(root.get("task").get("id"), taskId);
    }

    // Фильтр по startDate (postedAt >= startDate)
    public static Specification<Comment> startDate(LocalDateTime startDate) {
        return (root, query, criteriaBuilder) ->
                startDate == null
                        ? criteriaBuilder.conjunction()
                        : criteriaBuilder.greaterThanOrEqualTo(root.get("postedAt"), startDate);
    }

    // Фильтр по endDate (postedAt <= endDate)
    public static Specification<Comment> endDate(LocalDateTime endDate) {
        return (root, query, criteriaBuilder) ->
                endDate == null
                        ? criteriaBuilder.conjunction()
                        : criteriaBuilder.lessThanOrEqualTo(root.get("postedAt"), endDate);
    }

    // Фильтр по wasEdited
    public static Specification<Comment> wasEdited(Boolean wasEdited) {
        return (root, query, criteriaBuilder) -> {
            if (wasEdited == null) {
                return criteriaBuilder.conjunction();
            }
            Predicate editedPredicate = criteriaBuilder.notEqual(root.get("postedAt"), root.get("lastEditedAt"));
            return wasEdited ? editedPredicate : criteriaBuilder.not(editedPredicate);
        };
    }

    // Фильтр по минимальной длине текста
    public static Specification<Comment> minLength(Integer minLength) {
        return (root, query, criteriaBuilder) ->
                minLength == null
                        ? criteriaBuilder.conjunction()
                        : criteriaBuilder.greaterThanOrEqualTo(criteriaBuilder.length(root.get("text")), minLength);
    }

    // Фильтр по максимальной длине текста
    public static Specification<Comment> maxLength(Integer maxLength) {
        return (root, query, criteriaBuilder) ->
                maxLength == null
                        ? criteriaBuilder.conjunction()
                        : criteriaBuilder.lessThanOrEqualTo(criteriaBuilder.length(root.get("text")), maxLength);
    }

    // Общий фильтр для notDeleted
    public static Specification<Comment> notDeleted() {
        return (root, query, criteriaBuilder) ->
                criteriaBuilder.notEqual(root.get("state"), BaseEntity.State.DELETED);
    }
}
