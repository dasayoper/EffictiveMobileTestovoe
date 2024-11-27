package by.dasayoper.taskmanager.controller;

import by.dasayoper.taskmanager.dto.AccountDto;
import by.dasayoper.taskmanager.dto.form.AccountInfoForm;
import by.dasayoper.taskmanager.dto.page.AccountPage;
import by.dasayoper.taskmanager.dto.util.AccountFilterParameters;
import by.dasayoper.taskmanager.exception.UserAccountNotFoundException;
import by.dasayoper.taskmanager.service.AccountService;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;

import java.util.Arrays;
import java.util.List;
import java.util.UUID;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureMockMvc
public class AccountControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private AccountService accountService;

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Nested
    @DisplayName("getAccount() is working")
    class GetAccount {
        @Test
        @WithMockUser(username = "testuser", authorities = "ADMIN")
        void getAccount_ShouldReturnAccount_WhenAccountExists() throws Exception {
            UUID accountId = UUID.randomUUID();
            AccountDto account = AccountDto.builder()
                    .id(accountId)
                    .firstName("John")
                    .lastName("Doe")
                    .email("john.doe@example.com")
                    .role("COMMON_USER")
                    .build();

            when(accountService.getById(accountId)).thenReturn(account);

            mockMvc.perform(get("/accounts/" + accountId))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.id").value(accountId.toString()))
                    .andExpect(jsonPath("$.firstName").value("John"))
                    .andExpect(jsonPath("$.role").value("COMMON_USER"));
        }

        @Test
        @WithMockUser(username = "testuser", authorities = "ADMIN")
        void getAccount_ShouldReturn404NotFound_WhenAccountDoesNotExist() throws Exception {
            UUID accountId = UUID.randomUUID();

            when(accountService.getById(accountId)).thenThrow(new UserAccountNotFoundException("Account not found with id: " + accountId));

            mockMvc.perform(get("/accounts/" + accountId))
                    .andExpect(status().isNotFound())
                    .andExpect(jsonPath("$.code").value(404))
                    .andExpect(jsonPath("$.status").value("NOT_FOUND"))
                    .andExpect(jsonPath("$.message").value("Account not found with id: " + accountId));
        }
    }

    @Nested
    @DisplayName("getAllAccounts() is working")
    class GetAllAccounts {

        private List<AccountDto> accounts;

        @BeforeEach
        void setUp() {
            accounts = Arrays.asList(
                    AccountDto.builder()
                            .id(UUID.randomUUID())
                            .firstName("John")
                            .lastName("Doe")
                            .email("john.doe@example.com")
                            .role("COMMON_USER")
                            .build(),
                    AccountDto.builder()
                            .id(UUID.randomUUID())
                            .firstName("Jane")
                            .lastName("Smith")
                            .email("jane.smith@example.com")
                            .role("ADMIN")
                            .build()
            );
        }

        @Test
        @WithMockUser(username = "testuser", authorities = "ADMIN")
        void getAllAccounts_ShouldReturnFilteredAccounts_WhenFilteringByFirstName() throws Exception {
            AccountFilterParameters filterParameters = AccountFilterParameters.buildAccountFilterParameters("John", null, null, null, 0, 10);
            AccountPage accountPage = new AccountPage(accounts, 1, 2L, 0);

            when(accountService.getAllFiltered(any(AccountFilterParameters.class))).thenReturn(accountPage);

            mockMvc.perform(get("/accounts")
                            .param("firstName", "John")
                            .param("size", "10")
                            .param("page", "0"))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.accounts.length()").value(2))
                    .andExpect(jsonPath("$.accounts[0].firstName").value("John"))
                    .andExpect(jsonPath("$.accounts[1].firstName").value("Jane"))
                    .andExpect(jsonPath("$.totalElements").value(2))
                    .andExpect(jsonPath("$.totalPages").value(1))
                    .andExpect(jsonPath("$.currentPage").value(0));
        }
    }

    @Nested
    @DisplayName("updateAccount() is working")
    class UpdateAccount {
        @Test
        @WithMockUser(username = "testuser", authorities = "ADMIN")
        void updateAccount_ShouldReturnUpdatedAccount() throws Exception {
            UUID accountId = UUID.randomUUID();
            AccountInfoForm form = AccountInfoForm.builder()
                    .firstName("Updated")
                    .lastName("User")
                    .build();
            AccountDto updatedAccount = AccountDto.builder()
                    .id(accountId)
                    .firstName("Updated")
                    .lastName("User")
                    .email("updated.user@example.com")
                    .role("COMMON_USER")
                    .build();

            when(accountService.updateById(eq(accountId), any(AccountInfoForm.class))).thenReturn(updatedAccount);

            mockMvc.perform(patch("/accounts/" + accountId)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(form)))
                    .andExpect(status().isAccepted())
                    .andExpect(jsonPath("$.firstName").value("Updated"))
                    .andExpect(jsonPath("$.lastName").value("User"));
        }

        @Test
        @WithMockUser(username = "testuser", authorities = "ADMIN")
        void updateAccount_ShouldReturn400BadRequest_WhenFormIsIncorrect() throws Exception {
            UUID accountId = UUID.randomUUID();
            AccountInfoForm form = AccountInfoForm.builder()
                    .firstName("John")
                    .lastName("")
                    .build();

            mockMvc.perform(patch("/accounts/" + accountId)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(form)))
                    .andExpect(status().isBadRequest())
                    .andExpect(jsonPath("$.errors.size()").value(1))
                    .andExpect(jsonPath("$.errors[?(@.field=='lastName')].message")
                            .value("Фамилия должна начинаться с заглавной буквы, содержать только буквы и иметь длину от 2 до 30 символов"));
        }
    }
}

