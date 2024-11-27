package by.dasayoper.taskmanager.dto.util;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Data;

/**
 * Класс, который содержит критерии фильтрации задач.
 * <p>
 * Данный класс используется для задания параметров поиска задач по их заголовку, описанию, статусу, приоритету, автору и исполнителю.
 * </p>
 * Содержит следующие параметры фильтрации:
 * <ul>
 *     <li>Заголовок задачи {@link #title}, частичное или полное совпадение.</li>
 *     <li>Описание задачи {@link #description}, частичное или полное совпадение.</li>
 *     <li>Статус задачи {@link #status}, например, NEW, ASSIGNED, CLOSED и другие.</li>
 *     <li>Приоритет задачи {@link #priority}, например, HIGH, MEDIUM, LOW.</li>
 *     <li>Идентификатор автора задачи {@link #authorId}.</li>
 *     <li>Идентификатор исполнителя задачи {@link #executorId}.</li>
 *     <li>Номер страницы {@link #page} для пагинации.</li>
 *     <li>Размер страницы {@link #size} для пагинации.</li>
 * </ul>
 */
@Data
@Schema(description = "Объект, содержащий параметры фильтрации задач")
public class TaskFilterParameters {
    private String title;
    private String description;
    private String status;
    private String priority;
    private String authorId;
    private String executorId;
    private int page;
    private int size;

    /**
     * Служебный метод для получения объекта класса {@link TaskFilterParameters}, содержащего набор критериев фильтрации
     *
     * @return объект класса {@link TaskFilterParameters}
     */
    public static TaskFilterParameters createTaskFilterParameters(String title,
                                                            String description,
                                                            String status,
                                                            String priority,
                                                            String authorId,
                                                            String executorId,
                                                            int page,
                                                            int size) {
        TaskFilterParameters filterParameters = new TaskFilterParameters();
        filterParameters.setTitle(title);
        filterParameters.setDescription(description);
        filterParameters.setStatus(status);
        filterParameters.setPriority(priority);
        filterParameters.setAuthorId(authorId);
        filterParameters.setExecutorId(executorId);
        filterParameters.setPage(page);
        filterParameters.setSize(size);

        return filterParameters;
    }
}
