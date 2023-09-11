use std::fmt::Write;

macro_rules! consume_integral_in_range {
    ($self:expr, $min:expr, $max:expr, $it:ty) => {{
        assert!($min <= $max);
        let range: $it = $max.checked_sub($min).unwrap_or(<$it>::MAX);
        let mut res: $it = 0;
        let mut offset: usize = 0;

        let mut bytes_used = 0;
        let remaining_bytes = $self.remaining_bytes();

        while (offset < std::mem::size_of::<$it>() * u8::BITS as usize)
            && ((range >> offset) > 0)
            && (bytes_used != remaining_bytes)
        {
            bytes_used += 1;
            let index = remaining_bytes - bytes_used;

            res = (std::num::Wrapping(res) << u8::BITS as usize).0 | $self.data[index] as $it;
            offset += u8::BITS as usize;
        }

        if range as $it != <$it>::MAX {
            res = res % (range as $it + 1);
        }

        $self.cursor += bytes_used;

        (std::num::Wrapping($min) + std::num::Wrapping(res)).0
    }};
}

macro_rules! consume_probability {
    ($self:expr, f32) => {
        $self.consume_u32() as f32 / u32::MAX as f32
    };

    ($self:expr, f64) => {
        $self.consume_u64() as f64 / u64::MAX as f64
    };
}

macro_rules! consume_floating_point_in_range {
    ($self:expr, $min:expr, $max:expr, $it:ty) => {{
        assert!($min < $max);
        let range: $it;
        let mut res = $min;
        let zero: $it = 0.0;

        if $max > zero && $min < zero && $max > $min + <$it>::MAX {
            range = ($max / 2.0) - ($min / 2.0);
            if $self.consume_bool() {
                res += range;
            }
        } else {
            range = $max - $min;
        }

        res + range
    }};

    ($self:expr, $min:expr, $max:expr, f32) => {
        consume_floating_point_in_range!($self, $min, $max, f32) * $self.consume_probability_f32()
    };

    ($self:expr, $min:expr, $max:expr, f64) => {
        consume_floating_point_in_range!($self, $min, $max, f64) * $self.consume_probability_f64()
    };
}

macro_rules! impl_consume_integral_in_range {
    ($name:ident, $it:ty) => {
        #[doc = concat!(
"Consumes `std::mem::sizeof::<", stringify!($it), ">()` bytes from the provider and returns a value in the range `min..max`\n\n\
# Arguments:\n\
\n\
* `min`: The minimum value in the range\n\
* `max`: The maximum value in the range\n\
\n\
returns: The value between `min..max`")]
        pub fn $name(&mut self, min: $it, max: $it) -> $it {
            consume_integral_in_range!(self, min, max, $it)
        }
    };
}

macro_rules! impl_consume_integral {
    ($name:ident, $it:ty) => {
        #[doc = concat!(
"Consumes `std::mem::sizeof::<", stringify!($it), ">()` bytes from the provider an returns value in the range `",
stringify!($it), "::MIN..", stringify!($it), "::MAX`\n\
\n\
returns: The value between `", stringify!($it), "::MIN..", stringify!($it), "::MAX`")]
        pub fn $name(&mut self) -> $it {
            consume_integral_in_range!(self, <$it>::MIN, <$it>::MAX, $it)
        }
    };
}

macro_rules! impl_consume_floating_point_in_range {
    ($name:ident, f32) => {
        /// Consumes `std::mem::sizeof::<f32>()` bytes from the provider and returns a value in the range `min..max`
        ///
        /// # Arguments:
        ///
        /// * `min`: The minimum value in the range
        /// * `max`: The maximum value in the range
        ///
        /// returns: The value between `min..max`
        pub fn $name(&mut self, min: f32, max: f32) -> f32 {
            consume_floating_point_in_range!(self, min, max, f32)
        }
    };

    ($name:ident, f64) => {
        /// Consumes `std::mem::sizeof::<f64>()` bytes from the provider and returns a value in the range `min..max`
        ///
        /// # Arguments:
        ///
        /// * `min`: The minimum value in the range
        /// * `max`: The maximum value in the range
        ///
        /// returns: The value between `min..max`
        pub fn $name(&mut self, min: f64, max: f64) -> f64 {
            consume_floating_point_in_range!(self, min, max, f64)
        }
    };
}

macro_rules! impl_consume_floating_point {
    ($name:ident, f32) => {
        /// Consumes `std::mem::sizeof::<f32>()` bytes from the provider and returns a value in the range `f32::MIN..f32::MAX`
        ///
        /// returns: The value between `f32::MIN..f32::MAX`
        pub fn $name(&mut self) -> f32 {
            consume_floating_point_in_range!(self, f32::MIN, f32::MAX, f32)
        }
    };

    ($name:ident, f64) => {
        /// Consumes `std::mem::sizeof::<f64>()` bytes from the provider and returns a value in the range `f64::MIN..f64::MAX`
        ///
        /// returns: The value between `f64::MIN..f64::MAX`
        pub fn $name(&mut self) -> f64 {
            consume_floating_point_in_range!(self, f64::MIN, f64::MAX, f64)
        }
    };
}

#[derive(Debug)]
pub struct FuzzedDataProvider<'a> {
    data: &'a [u8],
    cursor: usize,
}

impl<'a> FuzzedDataProvider<'a> {
    /// Creates a new `FuzzedDataProvider`
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, cursor: 0 }
    }

    #[inline]
    fn has_remaining_bytes(&self) -> bool {
        self.remaining_bytes() != 0
    }

    /// Returns the number of remaining bytes the provider has
    ///
    /// returns: The number of remaining bytes
    #[inline]
    pub fn remaining_bytes(&self) -> usize {
        self.data.len() - self.cursor
    }

    /// Consumes `num_bytes` from the provider and returns them.
    /// If the provider doesn't have `num_bytes` remaining, then it will
    /// return the remaining bytes
    ///
    /// # Arguments
    ///
    /// * `num_bytes`: The number of bytes to consume
    ///
    /// returns: The bytes from the provider
    ///
    /// # Examples
    ///
    /// ```
    /// use fuzzed_data_provider_rs::FuzzedDataProvider;
    ///
    /// fn main() {
    ///     let mut fp = FuzzedDataProvider::new(&[1, 2, 3, 4]);
    ///     assert_eq!(fp.consume_bytes(2), vec![1, 2]);
    /// }
    /// ```
    pub fn consume_bytes(&mut self, num_bytes: usize) -> Vec<u8> {
        let num_bytes = num_bytes.min(self.remaining_bytes());

        let mut res = Vec::with_capacity(num_bytes);
        res.extend_from_slice(&self.data[self.cursor..num_bytes]);

        self.cursor += num_bytes;

        res
    }

    /// Consumes `num_bytes` from the provider and returns them as a `String`.
    /// If the provider doesn't have `num_bytes` remaining, then it will
    /// return the remaining bytes
    ///
    /// # Arguments
    ///
    /// * `num_bytes`: The number of bytes to consume
    ///
    /// returns: The bytes from the provider as a String
    ///
    /// # Examples
    ///
    /// ```
    /// use fuzzed_data_provider_rs::FuzzedDataProvider;
    ///
    /// fn main() {
    ///     let mut fp = FuzzedDataProvider::new(&[b'A', b'B', b'C']);
    ///     assert_eq!(fp.consume_bytes_as_string(2), "AB");
    /// }
    /// ```
    pub fn consume_bytes_as_string(&mut self, num_bytes: usize) -> String {
        let num_bytes = num_bytes.min(self.remaining_bytes());

        let res = String::from_utf8_lossy(&self.data[self.cursor..num_bytes]).to_string();

        self.cursor += num_bytes;

        res
    }

    /// Consumes the data provider and returns the remaining bytes if any.
    ///
    /// returns: The remaining bytes
    ///
    /// # Examples
    ///
    /// ```
    /// use fuzzed_data_provider_rs::FuzzedDataProvider;
    ///
    /// fn main() {
    ///     let fp = FuzzedDataProvider::new(&[1, 2, 3]);
    ///     assert_eq!(fp.consume_remaining_bytes(), vec![1, 2, 3]);
    /// }
    /// ```
    pub fn consume_remaining_bytes(mut self) -> Vec<u8> {
        self.consume_bytes(self.remaining_bytes())
    }

    /// Consumes the data provider and returns the remaining bytes if any as a `String`
    ///
    ///
    /// returns: The remaining bytes from the provider as a String
    ///
    /// # Examples
    ///
    /// ```
    /// use fuzzed_data_provider_rs::FuzzedDataProvider;
    ///
    /// fn main() {
    ///     let fp = FuzzedDataProvider::new(&[b'A', b'B', b'C']);
    ///     assert_eq!(fp.consume_remaining_bytes_as_string(), "ABC");
    /// }
    /// ```
    pub fn consume_remaining_bytes_as_string(mut self) -> String {
        self.consume_bytes_as_string(self.remaining_bytes())
    }

    /// Consumes at most `max_len` bytes from the provider as a `String`.
    /// If a backslash (\) is encountered then the consuming will stop earlier.
    /// If provider has less bytes remaining than `max_len` then the number of remaining
    /// bytes will be consumed at most.
    ///
    /// # Arguments
    ///
    /// * `max_len`: The maximum number of bytes to consume
    ///
    /// returns: The bytes consumed as a `String`
    ///
    /// # Examples
    ///
    /// ```
    /// use fuzzed_data_provider_rs::FuzzedDataProvider;
    ///
    /// fn main() {
    ///     let mut fp = FuzzedDataProvider::new(&[b'A', b'B', b'\\', b'C', b'D']);
    ///     assert_eq!(fp.consume_random_length_string(4), "AB");
    ///     assert_eq!(fp.consume_random_length_string(3), "D");
    /// }
    /// ```
    pub fn consume_random_length_string(&mut self, max_len: usize) -> String {
        let mut res = String::with_capacity(max_len.min(self.remaining_bytes()));
        let mut i = 0usize;
        while i != max_len && self.has_remaining_bytes() {
            let mut next = self.data[self.cursor] as char;
            self.cursor += 1;

            if next == '\\' && self.has_remaining_bytes() {
                next = self.data[self.cursor] as char;
                self.cursor += 1;

                if next != '\\' {
                    break;
                }
            }

            i += 1;

            if write!(res, "{next}").is_err() {
                break;
            }
        }

        res.shrink_to_fit();
        res
    }

    /// Consumes a bytes from the provider and returns that as a `bool`
    ///
    /// returns: The byte consumed as a `bool`
    ///
    /// # Examples
    ///
    /// ```
    /// use fuzzed_data_provider_rs::FuzzedDataProvider;
    ///
    /// fn main() {
    ///     let mut fp = FuzzedDataProvider::new(&[2, 1]);
    ///     assert_eq!(fp.consume_bool(), true);
    ///     assert_eq!(fp.consume_bool(), false);
    /// }
    /// ```
    pub fn consume_bool(&mut self) -> bool {
        (1 & self.consume_u8()) != 0
    }

    /// Consumes the required bytes from the provider and returns a probability as `f32`.
    /// Probability is a value between `0.0` and `1.0`
    ///
    /// returns: The probability value
    ///
    /// # Examples
    ///
    /// ```
    /// use fuzzed_data_provider_rs::FuzzedDataProvider;
    ///
    /// fn main() {
    ///     let mut fp = FuzzedDataProvider::new(&[255, 0]);
    ///     assert!((0.0f32..1.0f32).contains(&fp.consume_probability_f32()));
    /// }
    /// ```
    pub fn consume_probability_f32(&mut self) -> f32 {
        consume_probability!(self, f32)
    }

    /// Consumes the required bytes from the provider and returns a probability as `f64`.
    /// Probability is a value between `0.0` and `1.0`
    ///
    /// returns: The probability value
    ///
    /// # Examples
    ///
    /// ```
    /// use fuzzed_data_provider_rs::FuzzedDataProvider;
    ///
    /// fn main() {
    ///     let mut fp = FuzzedDataProvider::new(&[255, 0]);
    ///     assert!((0.0f64..1.0f64).contains(&fp.consume_probability_f64()));
    /// }
    /// ```
    pub fn consume_probability_f64(&mut self) -> f64 {
        consume_probability!(self, f64)
    }

    /// Consumes `std::mem::sizeof::<usize>()` bytes from the provider
    /// constraining the value between 0 and `slice.len() - 1`.
    /// This value is then used as an index to the given `slice` and returns
    /// a copy of the value which belongs to that index.
    ///
    /// # Arguments
    ///
    /// * `slice`:
    /// The slice to index and retrieve the value from
    ///
    /// returns: The value from the slice if the slice is not empty or `None` otherwise.
    ///
    /// # Examples
    ///
    /// ```
    /// use fuzzed_data_provider_rs::FuzzedDataProvider;
    ///
    /// fn main() {
    ///     let values = [1, 2, 3, 4, 5];
    ///     let mut fp = FuzzedDataProvider::new(&[2, 3]);
    ///     assert_eq!(fp.pick_value_from(&values), Some(4));
    ///     assert_eq!(fp.pick_value_from(&values), Some(3));
    /// }
    /// ```
    pub fn pick_value_from<T: Clone, S: AsRef<[T]>>(&mut self, slice: S) -> Option<T> {
        let slice = slice.as_ref();
        (!slice.is_empty()).then(|| slice[self.consume_usize_in_range(0, slice.len() - 1)].clone())
    }

    /// Consumes `std::mem::sizeof::<usize>()` bytes from the provider
    /// constraining the value between 0 and `slice.len() - 1`.
    /// This value is then used as an index to the given `slice` and returns
    /// a copy of the value which belongs to that index.
    ///
    /// # Arguments
    ///
    /// * `slice`:
    /// The slice to index and retrieve the value from
    ///
    /// returns: The value from the slice if the slice is not empty or `T::default()` otherwise.
    ///
    /// # Examples
    ///
    /// ```
    /// use fuzzed_data_provider_rs::FuzzedDataProvider;
    ///
    /// fn main() {
    ///     let values: &[u32] = &[];
    ///     let mut fp = FuzzedDataProvider::new(&[2, 3]);
    ///     assert_eq!(fp.pick_value_from_or_default(values), u32::default());
    /// }
    /// ```
    pub fn pick_value_from_or_default<T: Clone + Default, S: AsRef<[T]>>(&mut self, slice: S) -> T {
        self.pick_value_from(slice).unwrap_or_default()
    }

    impl_consume_integral_in_range!(consume_i8_in_range, i8);
    impl_consume_integral_in_range!(consume_u8_in_range, u8);
    impl_consume_integral_in_range!(consume_i16_in_range, i16);
    impl_consume_integral_in_range!(consume_u16_in_range, u16);
    impl_consume_integral_in_range!(consume_i32_in_range, i32);
    impl_consume_integral_in_range!(consume_u32_in_range, u32);
    impl_consume_integral_in_range!(consume_i64_in_range, i64);
    impl_consume_integral_in_range!(consume_u64_in_range, u64);
    impl_consume_integral_in_range!(consume_i128_in_range, i128);
    impl_consume_integral_in_range!(consume_u128_in_range, u128);
    impl_consume_integral_in_range!(consume_usize_in_range, usize);
    impl_consume_integral_in_range!(consume_isize_in_range, isize);

    impl_consume_integral!(consume_i8, i8);
    impl_consume_integral!(consume_u8, u8);
    impl_consume_integral!(consume_i16, i16);
    impl_consume_integral!(consume_u16, u16);
    impl_consume_integral!(consume_i32, i32);
    impl_consume_integral!(consume_u32, u32);
    impl_consume_integral!(consume_i64, i64);
    impl_consume_integral!(consume_u64, u64);
    impl_consume_integral!(consume_i128, i128);
    impl_consume_integral!(consume_u128, u128);
    impl_consume_integral!(consume_usize, usize);
    impl_consume_integral!(consume_isize, isize);

    impl_consume_floating_point_in_range!(consume_f32_in_range, f32);
    impl_consume_floating_point_in_range!(consume_f64_in_range, f64);

    impl_consume_floating_point!(consume_f32, f32);
    impl_consume_floating_point!(consume_f64, f64);
}

#[cfg(test)]
mod tests {
    use crate::FuzzedDataProvider;

    #[test]
    fn test_consume_empty_returns_empty_vec() {
        let fp = FuzzedDataProvider::new(&[]);
        assert_eq!(fp.consume_remaining_bytes(), vec![]);
    }

    #[test]
    fn test_consume_empty_as_string_returns_empty_string() {
        let fp = FuzzedDataProvider::new(&[]);
        assert_eq!(fp.consume_remaining_bytes_as_string(), String::new());
    }

    #[test]
    fn test_consume_remaining_as_string() {
        let fp = FuzzedDataProvider::new(&[b'@', b'A', b'B']);
        assert_eq!(fp.consume_remaining_bytes_as_string(), "@AB");
    }

    #[test]
    fn test_consume_bytes() {
        let mut fp = FuzzedDataProvider::new(&[1, 2, 3]);
        assert_eq!(fp.consume_bytes(2), vec![1, 2]);
    }

    #[test]
    fn test_consume_probability_f32() {
        let mut fp = FuzzedDataProvider::new(&[255, 0]);
        assert!((0.0f32..1.0f32).contains(&fp.consume_probability_f32()));
    }

    #[test]
    fn test_consume_probability_f64() {
        let mut fp = FuzzedDataProvider::new(&[1, 200, 10, 20]);
        assert!((0.0f64..1.0f64).contains(&fp.consume_probability_f64()));
    }

    #[test]
    fn test_consume_integral_u8() {
        let mut fp = FuzzedDataProvider::new(&[255, 1]);
        assert_eq!(fp.consume_u8(), 1);
        assert_eq!(fp.consume_u8(), 255);
    }

    #[test]
    fn test_consume_integral_i8() {
        let mut fp = FuzzedDataProvider::new(&[255, 1]);
        assert_eq!(fp.consume_i8(), -127);
        assert_eq!(fp.consume_i8(), 127);
    }

    #[test]
    fn test_consume_integral_u16() {
        let mut fp = FuzzedDataProvider::new(&[1, 1]);
        assert_eq!(fp.consume_u16(), 257);
    }

    #[test]
    fn test_consume_integral_i16() {
        let mut fp = FuzzedDataProvider::new(&[1, 1]);
        assert_eq!(fp.consume_i16(), -32511);
    }

    #[test]
    fn test_consume_integral_u32_without_sufficient_bytes() {
        let mut fp = FuzzedDataProvider::new(&[1, 1]);
        assert_eq!(fp.consume_u32(), 257);
    }

    #[test]
    fn test_consume_integral_in_range_u8() {
        let mut fp = FuzzedDataProvider::new(&[255]);
        assert_eq!(fp.consume_u8_in_range(1, 10), 6);
    }

    #[test]
    fn test_consume_bool() {
        let mut fp = FuzzedDataProvider::new(&[0, 1, 11]);
        assert_eq!(fp.consume_bool(), true);
        assert_eq!(fp.consume_bool(), true);
        assert_eq!(fp.consume_bool(), false);
    }

    #[test]
    fn test_consume_floating_point_f32() {
        let mut fp = FuzzedDataProvider::new(&[1, 2, 3, 4, 5]);
        assert_eq!(fp.consume_f32(), 3.4028235e38);
    }

    #[test]
    fn test_consume_floating_point_f64() {
        let mut fp = FuzzedDataProvider::new(&[1, 2, 3, 4, 5, 6, 7, 8, 11]);
        assert_eq!(fp.consume_f64(), 1.7976931348623157e308);
    }

    #[test]
    fn test_consume_floating_point_in_range_f32() {
        let mut fp = FuzzedDataProvider::new(&[1, 2, 3, 4, 5]);
        assert_eq!(fp.consume_f32_in_range(1.0, 1.5), 1.5);
    }

    #[test]
    fn test_consume_floating_point_in_range_f64() {
        let mut fp = FuzzedDataProvider::new(&[1, 2, 3, 4, 5, 6, 7, 8, 11]);
        assert_eq!(fp.consume_f64_in_range(1.1, 1.9), 1.9);
    }

    #[test]
    fn test_pick_value_from() {
        let values = [1, 2, 3, 4, 5];
        let mut fp = FuzzedDataProvider::new(&[0, 1, 2, 3]);
        assert_eq!(fp.pick_value_from(&values), Some(4));
        assert_eq!(fp.pick_value_from(&values), Some(3));
    }

    #[test]
    fn test_consume_random_length_string() {
        let mut fp = FuzzedDataProvider::new(&[b'@', b'1', b'5', b'\\', b'7', b'8', b'9']);
        assert_eq!(fp.consume_random_length_string(10), "@15");
        assert_eq!(fp.consume_random_length_string(10), "89");
    }

    #[test]
    fn test_consume_integral_from_empty_provider() {
        let mut fp = FuzzedDataProvider::new(&[]);
        assert_eq!(fp.consume_u32(), 0);
    }

    #[test]
    fn test_consume_floating_point_from_empty_provider() {
        let mut fp = FuzzedDataProvider::new(&[]);
        assert_eq!(fp.consume_f64(), 0.0);
    }
}
