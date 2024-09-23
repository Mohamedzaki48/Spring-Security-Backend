package com.springproject.springbootsecurity.repository;
import com.springproject.springbootsecurity.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import java.util.Optional;
@Repository
public interface UserRepository extends JpaRepository<User, Long> {
    //User findByUsername(String username);
}
