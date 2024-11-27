package by.dasayoper.taskmanager.dto.util;

import lombok.Data;

/**
 * Класс, который содержит критерии фильтрации комментариев.
 * <p>
 * Данный класс используется для задания параметров поиска комментариев по их содержимому, автору, задаче, датам и другим характеристикам.
 * </p>
 * Содержит следующие параметры фильтрации:
 * <ul>
 *     <li>Текст комментария {@link #text}, частичное или полное совпадение.</li>
 *     <li>Идентификатор автора комментария {@link #authorId}.</li>
 *     <li>Идентификатор задачи {@link #taskId}, к которой относится комментарий.</li>
 *     <li>Начало периода для фильтрации по дате {@link #startDate}, в формате даты.</li>
 *     <li>Конец периода для фильтрации по дате {@link #endDate}, в формате даты.</li>
 *     <li>Признак отредактированного комментария {@link #wasEdited}, указывает на наличие изменений в комментарии.</li>
 *     <li>Минимальная длина текста комментария {@link #minLength}.</li>
 *     <li>Максимальная длина текста комментария {@link #maxLength}.</li>
 *     <li>Номер страницы {@link #page} для пагинации.</li>
 *     <li>Размер страницы {@link #size} для пагинации.</li>
 * </ul>
 */
@Data
public class CommentFilterParameters {
    private String text;
    private String authorId;
    private String taskId;
    private String startDate;
    private String endDate;
    private String wasEdited;
    private String minLength;
    private String maxLength;
    private int page;
    private int size;

    /**
     * Служебный метод для получения объекта класса {@link CommentFilterParameters}, содержащего набор критериев фильтрации
     *
     * @return объект класса {@link CommentFilterParameters}
     */
    public static CommentFilterParameters createCommentFilterParameters(String text, String authorId, String taskId, String startDate, String endDate, String wasEdited, String minLength, String maxLength, int page, int size) {
        CommentFilterParameters filterParameters = new CommentFilterParameters();
        filterParameters.setText(text);
        filterParameters.setAuthorId(authorId);
        filterParameters.setTaskId(taskId);
        filterParameters.setStartDate(startDate);
        filterParameters.setEndDate(endDate);
        filterParameters.setWasEdited(wasEdited);
        filterParameters.setMinLength(minLength);
        filterParameters.setMaxLength(maxLength);
        filterParameters.setPage(page);
        filterParameters.setSize(size);

        return filterParameters;
    }
}
