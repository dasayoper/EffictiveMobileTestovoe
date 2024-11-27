package by.dasayoper.taskmanager.dto.util;

import lombok.Data;

/**
 * Класс, который содержит критерии фильтрации аккаунтов.
 * <p>
 * Данный класс используется для задания параметров поиска пользователей по их личным данным, статусу задач, а также для
 * пагинации результатов.
 * </p>
 * Содержит следующие параметры фильтрации:
 * <ul>
 *     <li>Имя пользователя {@link #firstName}, частичное или полное совпадение.</li>
 *     <li>Фамилия пользователя {@link #lastName}, частичное или полное совпадение.</li>
 *     <li>Email {@link #email} пользователя, частичное или полное совпадение.</li>
 *     <li>Признак наличия задач в работе {@link #hasAssignedTasks}. Определяет, есть ли у пользователя задачи в статусах, отличных от NEW и CLOSED.</li>
 *     <li>Номер страницы {@link #page} для пагинации.</li>
 *     <li>Размер страницы {@link #size} для пагинации.</li>
 * </ul>
 */
@Data
public class AccountFilterParameters {
    private String firstName;
    private String lastName;
    private String email;
    private String hasAssignedTasks;
    private int page;
    private int size;

    /**
     * Служебный метод для получения объекта класса {@link AccountFilterParameters}, содержащего набор критериев фильтрации
     *
     * @return объект класса {@link AccountFilterParameters}
     */
    public static AccountFilterParameters buildAccountFilterParameters(String firstName, String lastName, String email,
                                                                 String hasAssignedTasks, int page, int size) {
        AccountFilterParameters filterParameters = new AccountFilterParameters();
        filterParameters.setFirstName(firstName);
        filterParameters.setLastName(lastName);
        filterParameters.setEmail(email);
        filterParameters.setHasAssignedTasks(hasAssignedTasks);
        filterParameters.setPage(page);
        filterParameters.setSize(size);
        return filterParameters;
    }
}
