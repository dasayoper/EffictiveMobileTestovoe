package by.dasayoper.taskmanager.service;

import by.dasayoper.taskmanager.dto.CommentDto;
import by.dasayoper.taskmanager.dto.form.CommentForm;
import by.dasayoper.taskmanager.dto.page.CommentPage;
import by.dasayoper.taskmanager.dto.util.CommentFilterParameters;

import java.util.List;
import java.util.UUID;

public interface CommentService {
    CommentDto getById(UUID id);
    List<CommentDto> getAll();
    CommentPage getAllFiltered(CommentFilterParameters filterParameters);
    CommentDto save(UUID taskId, CommentForm form);
    CommentDto updateById(UUID id, CommentForm commentForm);
    void deleteById(UUID id);
}
