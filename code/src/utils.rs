macro_rules! concat_into {
    ( $dst:expr, $( $x:expr ),* ) => {
        {
            let mut n = 0;
            $(
                n += $x.len();
                $dst[n - $x.len()..n].copy_from_slice($x);
            )*
            $dst
        }
    };
}

macro_rules! concat {
    ( $n:expr, $( $x:expr ),* ) => {
        {
            let mut dst = [0; $n];
            concat_into!(dst, $( $x ),*);
            dst
        }
    };
}
