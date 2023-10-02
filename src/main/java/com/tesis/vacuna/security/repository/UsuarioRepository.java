package com.tesis.vacuna.security.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.tesis.vacuna.security.entity.Usuario;
import com.tesis.vacuna.security.enums.RolNombre;

import java.util.List;
import java.util.Optional;

@Repository
public interface UsuarioRepository extends JpaRepository<Usuario, Integer> {
	Optional<Usuario> findByDni(String dni);

	boolean existsByDni(String dni);

	boolean existsByEmail(String email);

	List<Usuario> findByRolesRolNombre(RolNombre rolNombre);

}