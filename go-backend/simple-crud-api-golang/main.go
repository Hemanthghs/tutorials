package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
)

type Employee struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Position string `json:"position"`
}

var employees = map[string]Employee{}

func main() {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /", serverStatus)
	mux.HandleFunc("GET /employees", getEmployees)
	mux.HandleFunc("GET /employees/{id}", getEmployee)
	mux.HandleFunc("POST /employees", createEmployee)
	mux.HandleFunc("DELETE /employees/{id}", deleteEmployee)
	mux.HandleFunc("PUT /employees/{id}", updateEmployee)

	log.Println("Starting server on :8080")
	http.ListenAndServe(":8080", mux)

}

func serverStatus(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Server up and runnning...\n"))
}

func getEmployees(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(employees)
}

func getEmployee(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	employee, found := employees[id]

	w.Header().Set("Content-Type", "application/json")
	if found {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(employee)
	} else {
		w.WriteHeader(http.StatusInternalServerError)
		response := map[string]string{
			"message": fmt.Sprintf("Employee with id %s not found", id),
		}
		json.NewEncoder(w).Encode(response)
	}

}

func createEmployee(w http.ResponseWriter, r *http.Request) {
	var employee Employee
	if err := json.NewDecoder(r.Body).Decode(&employee); err != nil {
		http.Error(w, "Failed to decode request", http.StatusBadRequest)
		return
	}

	if employee.ID == "" {
		employee.ID = strconv.Itoa(len(employees) + 1)
	}

	_, exists := employees[employee.ID]
	if exists {
		http.Error(w, "Employee already exist", http.StatusConflict)
		return
	}

	employees[employee.ID] = employee

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(employee)
}

func deleteEmployee(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	_, exists := employees[id]
	if !exists {
		http.Error(w, "Employee not found", http.StatusNotFound)
		return
	}

	delete(employees, id)

	response := map[string]string{
		"message": fmt.Sprintf("Employee %s is deleted successfully", id),
	}
	json.NewEncoder(w).Encode(response)

}

func updateEmployee(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	var update Employee
	if err := json.NewDecoder(r.Body).Decode(&update); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	update.ID = id
	employees[id] = update

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(update)
}
