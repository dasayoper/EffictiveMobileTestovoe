package by.dasayoper.taskmanager.service;

import by.dasayoper.taskmanager.dto.AccountDto;
import by.dasayoper.taskmanager.dto.form.AccountInfoForm;
import by.dasayoper.taskmanager.dto.page.AccountPage;
import by.dasayoper.taskmanager.dto.util.AccountFilterParameters;

import java.util.List;
import java.util.UUID;

public interface AccountService {
    AccountDto getById(UUID id);
    List<AccountDto> getAll();
    AccountPage getAllFiltered(AccountFilterParameters filterParameters);
    AccountDto updateById(UUID id, AccountInfoForm form);

}
