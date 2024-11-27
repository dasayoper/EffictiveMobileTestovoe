package by.dasayoper.taskmanager.service;

import by.dasayoper.taskmanager.dto.TaskDto;
import by.dasayoper.taskmanager.dto.form.TaskForm;
import by.dasayoper.taskmanager.dto.form.TaskStatusForm;
import by.dasayoper.taskmanager.dto.page.TaskPage;
import by.dasayoper.taskmanager.dto.util.TaskFilterParameters;

import java.util.List;
import java.util.UUID;

public interface TaskService {
    TaskDto getById(UUID id);
    List<TaskDto> getAll();
    TaskPage getAllFiltered(TaskFilterParameters filterParameters);
    TaskDto save(TaskForm form);
    TaskDto updateById(UUID id, TaskForm form);
    void deleteById(UUID id);

    TaskDto updateTaskStatus(UUID id, TaskStatusForm form);
}
