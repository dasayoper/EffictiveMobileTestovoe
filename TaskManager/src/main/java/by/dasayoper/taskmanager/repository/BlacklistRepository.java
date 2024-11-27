package by.dasayoper.taskmanager.repository;

public interface BlacklistRepository {
    void save(String token);
    boolean exists(String token);

}

