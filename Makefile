all:
	go build cmd/cpu_tracer/cpu_tracer.go
	go build cmd/tracer/tracer.go
	go build cmd/webserver/webserver.go

clean:
	rm tracer webserver