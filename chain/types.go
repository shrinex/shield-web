package chain

type (
	SecurityBuilder[T any] interface {
		Build() T
	}

	SecurityConfigurer[T any, B SecurityBuilder[T]] interface {
		Order() int
		Configure(B)
	}
)
