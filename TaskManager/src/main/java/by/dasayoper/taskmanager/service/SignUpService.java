package by.dasayoper.taskmanager.service;

import by.dasayoper.taskmanager.dto.AccountDto;
import by.dasayoper.taskmanager.dto.form.SignUpForm;

public interface SignUpService {
    AccountDto signUp(SignUpForm form);
}
