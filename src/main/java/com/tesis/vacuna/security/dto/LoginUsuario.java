package com.tesis.vacuna.security.dto;

import javax.validation.constraints.NotBlank;

public class LoginUsuario {

	@NotBlank
	private String dni;

	private String password;

	private String fechaNacimiento;

	public String getDni() {
		return dni;
	}

	public void setDni(String dni) {
		this.dni = dni;
	}

	public String getPassword() {
		return fechaNacimiento;
	}

	public void setPassword(String password) {
		this.password = getFechaNacimiento();
	}

	public String getFechaNacimiento() {
		return fechaNacimiento;
	}

	public void setFechaNacimiento(String fechaNacimiento) {
		this.fechaNacimiento = fechaNacimiento;
	}

}