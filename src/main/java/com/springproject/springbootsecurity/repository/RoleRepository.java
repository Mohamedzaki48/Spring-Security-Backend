package com.springproject.springbootsecurity.repository;

import com.springproject.springbootsecurity.entity.Role;
import org.springframework.data.jpa.repository.JpaRepository;

public interface RoleRepository extends JpaRepository<Role, Long> {
}
