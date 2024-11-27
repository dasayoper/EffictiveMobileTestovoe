package by.dasayoper.taskmanager.service.impl;

import by.dasayoper.taskmanager.model.Account;
import by.dasayoper.taskmanager.security.details.AccountUserDetails;
import by.dasayoper.taskmanager.service.SecurityService;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

/**
 * Утилитный класс для получения авторизованного в данный момент пользователя.
 * Имеет единственный метод {@link SecurityServiceImpl#getAuthorizedAccount()}.
 */
@Service
public class SecurityServiceImpl implements SecurityService {
    /**
     * Метод для получения авторизованного пользователя.
     *
     * @return объект класса {@link Account}.
     * @throws AccessDeniedException если не удалось получить пользователя.
     */
    @Override
    public Account getAuthorizedAccount() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication != null && authentication.getPrincipal() instanceof AccountUserDetails) {
            return ((AccountUserDetails) authentication.getPrincipal()).getAccount();
        }
        throw new AccessDeniedException("Не удалось определить авторизованного пользователя");
    }
}
